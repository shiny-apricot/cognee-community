"""Packagist / Composer (PHP Package Registry) Data Source Connector for Cognee.

Table of Contents:
------------------
1. Constants & Data Structures
   - DOCUMENT_SOURCE_ATTR
   - PackagistSecurityAdvisory (@dataclass)
   - PackagistReleaseVersion (@dataclass)
   - PackagistPackageMetadata (@dataclass)
   - PackagistChangeAction (@dataclass)
2. Auth & Descriptive User-Agent Header Builder
   - build_packagist_headers
3. Composer Manifest Selection (composer.json & composer.lock)
   - parse_composer_manifest
4. Composer v2 Minified Metadata Expander (p2/{vendor}/{package}.json)
   - expand_composer_v2_versions
5. Package Metadata, Abandonment & Security Advisory Parsing
   - parse_security_advisories
   - parse_packagist_package
6. Incremental Cursor Feed (/metadata/changes.json) & Forget-on-Delete Sync
   - parse_metadata_changes
   - sync_packagist_packages
   - packagist_source
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
import json
import logging
from typing import Any

logger = logging.getLogger("cognee.connector.packagist")

DOCUMENT_SOURCE_ATTR = "_cognee_document_source"
DEFAULT_PACKAGIST_API_URL = "https://packagist.org"
DEFAULT_PACKAGIST_REPO_URL = "https://repo.packagist.org"
COMPOSER_V2_MINIFIED_MARKER = "composer/2.0"
COMPOSER_UNSET_SENTINEL = "__unset"


# ---------------------------------------------------------------------------
# 1. Constants & Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackagistSecurityAdvisory:
    """Security vulnerability advisory from Packagist /api/security-advisories/."""

    advisory_id: str  # e.g. "PKSA-dmw8-jd8k-q3c6"
    package_name: str
    title: str
    cve: str | None
    affected_versions: str
    link: str
    reported_at: str


@dataclass(frozen=True)
class PackagistReleaseVersion:
    """Expanded Composer release version record."""

    version: str
    version_normalized: str
    description: str
    license: list[str]
    require: dict[str, str]
    require_dev: dict[str, str]
    provide: dict[str, str]
    conflict: dict[str, str]
    php_constraint: str | None
    time: str
    abandoned: bool
    replacement_package: str | None


@dataclass(frozen=True)
class PackagistPackageMetadata:
    """Aggregated Packagist package metadata, releases, abandonment state, and advisories."""

    name: str  # "vendor/package"
    description: str
    repository: str | None
    maintainers: list[str]
    abandoned: bool
    replacement_package: str | None
    downloads_total: int
    favers: int
    latest_version: str
    versions: list[PackagistReleaseVersion]
    security_advisories: list[PackagistSecurityAdvisory] = field(default_factory=list)


@dataclass(frozen=True)
class PackagistChangeAction:
    """Single action item from GET /metadata/changes.json?since=<cursor>."""

    action_type: str  # "update" or "delete"
    package_name: str  # normalized without "~dev" suffix
    raw_package_field: str
    timestamp: int


# ---------------------------------------------------------------------------
# 2. Auth & Descriptive User-Agent Header Builder
# ---------------------------------------------------------------------------


def build_packagist_headers(
    bearer_token: str | None = None,
    contact_url_or_email: str = "https://github.com/topoteretes/cognee-community",
) -> dict[str, str]:
    """Construct HTTP headers compliant with Packagist API User-Agent policy and optional Private Packagist auth."""
    headers: dict[str, str] = {
        "User-Agent": f"cognee-community-connector-packagist/0.1.0 (+{contact_url_or_email})",
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


# ---------------------------------------------------------------------------
# 3. Composer Manifest Selection (composer.json & composer.lock)
# ---------------------------------------------------------------------------


def _is_composer_vendor_package(pkg_name: str) -> bool:
    """Return True if pkg_name is a valid vendor/package identifier (excluding php, ext-*, lib-*)."""
    lowered = pkg_name.strip().lower()
    if "/" not in lowered:
        return False
    if lowered == "php" or lowered.startswith(("ext-", "lib-", "composer-")):
        return False
    return True


def parse_composer_manifest(
    manifest_content: str | dict[str, Any],
    include_dev: bool = True,
) -> list[str]:
    """Extract sorted vendor/package names from composer.json or composer.lock.

    Args:
        manifest_content: Raw JSON string or parsed dictionary of composer.json or composer.lock.
        include_dev: Whether to include require-dev / packages-dev entries.

    Returns:
        Sorted list of unique `vendor/package` strings.
    """
    data = json.loads(manifest_content) if isinstance(manifest_content, str) else manifest_content
    found: set[str] = set()

    # composer.lock structure ("packages" and "packages-dev" lists)
    if "packages" in data and isinstance(data["packages"], list):
        for pkg in data["packages"]:
            if isinstance(pkg, dict):
                name = str(pkg.get("name", "")).strip().lower()
                if _is_composer_vendor_package(name):
                    found.add(name)
        if include_dev and isinstance(data.get("packages-dev"), list):
            for pkg in data["packages-dev"]:
                if isinstance(pkg, dict):
                    name = str(pkg.get("name", "")).strip().lower()
                    if _is_composer_vendor_package(name):
                        found.add(name)
        return sorted(found)

    # composer.json structure ("require" and "require-dev" dicts)
    require = data.get("require", {})
    if isinstance(require, dict):
        for name in require.keys():
            if _is_composer_vendor_package(name):
                found.add(name.strip().lower())

    if include_dev:
        require_dev = data.get("require-dev", {})
        if isinstance(require_dev, dict):
            for name in require_dev.keys():
                if _is_composer_vendor_package(name):
                    found.add(name.strip().lower())

    return sorted(found)


# ---------------------------------------------------------------------------
# 4. Composer v2 Minified Metadata Expander (p2/{vendor}/{package}.json)
# ---------------------------------------------------------------------------


def expand_composer_v2_versions(
    p2_payload: str | dict[str, Any],
    package_name: str | None = None,
) -> list[dict[str, Any]]:
    """Expand Composer 2 minified version entries (`minified: "composer/2.0"`).

    In Composer v2 metadata (`repo.packagist.org/p2/{vendor}/{package}.json`), the first version
    entry contains the full set of fields, and each subsequent entry only lists keys that changed
    since the previous entry, using `"__unset"` to delete keys that were removed.

    Args:
        p2_payload: Raw JSON string or dict from `p2/{vendor}/{package}.json`.
        package_name: Optional target `vendor/package` key; defaults to first key in `packages`.

    Returns:
        List of fully expanded version dictionaries.
    """
    data = json.loads(p2_payload) if isinstance(p2_payload, str) else p2_payload
    packages_map = data.get("packages", {})
    if not isinstance(packages_map, dict) or not packages_map:
        return []

    target_key = package_name.lower() if package_name and package_name.lower() in packages_map else next(iter(packages_map.keys()))
    raw_versions = packages_map.get(target_key, [])
    if not isinstance(raw_versions, list):
        return []

    is_minified = data.get("minified") == COMPOSER_V2_MINIFIED_MARKER
    if not is_minified:
        return [dict(v) for v in raw_versions if isinstance(v, dict)]

    expanded_list: list[dict[str, Any]] = []
    current_expanded: dict[str, Any] = {}

    for entry in raw_versions:
        if not isinstance(entry, dict):
            continue
        if not current_expanded:
            current_expanded = dict(entry)
        else:
            next_state = dict(current_expanded)
            for k, val in entry.items():
                if val == COMPOSER_UNSET_SENTINEL:
                    next_state.pop(k, None)
                else:
                    next_state[k] = val
            current_expanded = next_state
        expanded_list.append(dict(current_expanded))

    return expanded_list


# ---------------------------------------------------------------------------
# 5. Package Metadata, Abandonment & Security Advisory Parsing
# ---------------------------------------------------------------------------


def _parse_abandoned_field(raw_abandoned: Any) -> tuple[bool, str | None]:
    """Normalize Packagist `abandoned` field (can be False/None, True, or a replacement package string)."""
    if not raw_abandoned:
        return False, None
    if isinstance(raw_abandoned, str) and raw_abandoned.strip():
        return True, raw_abandoned.strip()
    return True, None


def parse_security_advisories(
    advisories_payload: str | dict[str, Any],
) -> dict[str, list[PackagistSecurityAdvisory]]:
    """Parse security advisories from POST https://packagist.org/api/security-advisories/.

    Returns:
        Mapping of lowercase `vendor/package` -> list of PackagistSecurityAdvisory.
    """
    data = json.loads(advisories_payload) if isinstance(advisories_payload, str) else advisories_payload
    raw_advisories = data.get("advisories", {})
    result: dict[str, list[PackagistSecurityAdvisory]] = {}

    if not isinstance(raw_advisories, dict):
        return result

    for pkg_name, adv_list in raw_advisories.items():
        if not isinstance(adv_list, list):
            continue
        parsed_list: list[PackagistSecurityAdvisory] = []
        for item in adv_list:
            if not isinstance(item, dict):
                continue
            parsed_list.append(
                PackagistSecurityAdvisory(
                    advisory_id=str(item.get("advisoryId", "")),
                    package_name=pkg_name.lower(),
                    title=str(item.get("title", "")),
                    cve=item.get("cve"),
                    affected_versions=str(item.get("affectedVersions", "")),
                    link=str(item.get("link", "")),
                    reported_at=str(item.get("reportedAt", "")),
                )
            )
        result[pkg_name.lower()] = parsed_list

    return result


def parse_packagist_package(
    package_api_json: str | dict[str, Any] | None = None,
    p2_metadata_json: str | dict[str, Any] | None = None,
    advisories: list[PackagistSecurityAdvisory] | None = None,
) -> PackagistPackageMetadata:
    """Combine Packagist main API package JSON, Composer v2 p2 metadata, and security advisories.

    Args:
        package_api_json: JSON from `https://packagist.org/packages/{vendor}/{package}.json`.
        p2_metadata_json: JSON from `https://repo.packagist.org/p2/{vendor}/{package}.json`.
        advisories: Optional list of security advisories for this package.

    Returns:
        PackagistPackageMetadata dataclass.
    """
    pkg_node: dict[str, Any] = {}
    if package_api_json is not None:
        raw_api = json.loads(package_api_json) if isinstance(package_api_json, str) else package_api_json
        pkg_node = raw_api.get("package", raw_api) if isinstance(raw_api, dict) else {}

    name = str(pkg_node.get("name", "")).lower()
    description = str(pkg_node.get("description", ""))
    repository = pkg_node.get("repository")
    maintainers = [
        str(m.get("name", ""))
        for m in pkg_node.get("maintainers", [])
        if isinstance(m, dict) and m.get("name")
    ]
    pkg_abandoned, pkg_replacement = _parse_abandoned_field(pkg_node.get("abandoned"))

    downloads_info = pkg_node.get("downloads", {})
    downloads_total = int(downloads_info.get("total", 0)) if isinstance(downloads_info, dict) else 0
    favers = int(pkg_node.get("favers", 0) or 0)

    # Collect raw version records from p2 metadata if provided, else from package_api_json["versions"]
    raw_version_records: list[dict[str, Any]] = []
    if p2_metadata_json is not None:
        raw_version_records = expand_composer_v2_versions(p2_metadata_json, package_name=name or None)
        if not name and raw_version_records:
            name = str(raw_version_records[0].get("name", "")).lower()
        if not description and raw_version_records:
            description = str(raw_version_records[0].get("description", ""))
    elif isinstance(pkg_node.get("versions"), dict):
        raw_version_records = [v for v in pkg_node["versions"].values() if isinstance(v, dict)]

    parsed_versions: list[PackagistReleaseVersion] = []
    for v_dict in raw_version_records:
        ver_str = str(v_dict.get("version", ""))
        ver_norm = str(v_dict.get("version_normalized", ver_str))
        v_abandoned, v_replacement = _parse_abandoned_field(v_dict.get("abandoned"))
        is_abandoned = v_abandoned or pkg_abandoned
        replacement = v_replacement or pkg_replacement

        require_map = {str(k): str(val) for k, val in (v_dict.get("require") or {}).items()} if isinstance(v_dict.get("require"), dict) else {}
        require_dev_map = {str(k): str(val) for k, val in (v_dict.get("require-dev") or {}).items()} if isinstance(v_dict.get("require-dev"), dict) else {}
        provide_map = {str(k): str(val) for k, val in (v_dict.get("provide") or {}).items()} if isinstance(v_dict.get("provide"), dict) else {}
        conflict_map = {str(k): str(val) for k, val in (v_dict.get("conflict") or {}).items()} if isinstance(v_dict.get("conflict"), dict) else {}
        php_constraint = require_map.get("php")

        lic_raw = v_dict.get("license", [])
        licenses = [str(x) for x in lic_raw] if isinstance(lic_raw, list) else ([str(lic_raw)] if lic_raw else [])

        parsed_versions.append(
            PackagistReleaseVersion(
                version=ver_str,
                version_normalized=ver_norm,
                description=str(v_dict.get("description", description)),
                license=licenses,
                require=require_map,
                require_dev=require_dev_map,
                provide=provide_map,
                conflict=conflict_map,
                php_constraint=php_constraint,
                time=str(v_dict.get("time", "")),
                abandoned=is_abandoned,
                replacement_package=replacement,
            )
        )

    latest_version = parsed_versions[0].version if parsed_versions else ""

    return PackagistPackageMetadata(
        name=name or "unknown/unknown",
        description=description,
        repository=repository,
        maintainers=maintainers,
        abandoned=pkg_abandoned or any(v.abandoned for v in parsed_versions),
        replacement_package=pkg_replacement or next((v.replacement_package for v in parsed_versions if v.replacement_package), None),
        downloads_total=downloads_total,
        favers=favers,
        latest_version=latest_version,
        versions=parsed_versions,
        security_advisories=list(advisories or []),
    )


# ---------------------------------------------------------------------------
# 6. Incremental Cursor Feed (/metadata/changes.json) & Forget-on-Delete Sync
# ---------------------------------------------------------------------------


def _normalize_changes_package_name(raw_name: str) -> str:
    """Strip Packagist `~dev` suffix from changes.json package names when matching release metadata."""
    cleaned = raw_name.strip().lower()
    if cleaned.endswith("~dev"):
        cleaned = cleaned[:-4]
    return cleaned


def parse_metadata_changes(
    changes_json: str | dict[str, Any],
) -> tuple[int, list[PackagistChangeAction]]:
    """Parse Packagist `/metadata/changes.json` high-resolution cursor and action stream.

    Args:
        changes_json: Raw JSON string or dict from `/metadata/changes.json`.

    Returns:
        Tuple of (cursor_timestamp: int, actions: list[PackagistChangeAction]).
    """
    data = json.loads(changes_json) if isinstance(changes_json, str) else changes_json
    timestamp = int(data.get("timestamp", 0) or 0)
    raw_actions = data.get("actions", [])

    actions: list[PackagistChangeAction] = []
    if isinstance(raw_actions, list):
        for act in raw_actions:
            if not isinstance(act, dict):
                continue
            raw_pkg = str(act.get("package", ""))
            actions.append(
                PackagistChangeAction(
                    action_type=str(act.get("type", "")).lower(),
                    package_name=_normalize_changes_package_name(raw_pkg),
                    raw_package_field=raw_pkg,
                    timestamp=int(act.get("time", 0) or 0),
                )
            )
    return timestamp, actions


def _render_packagist_searchable_text(meta: PackagistPackageMetadata) -> str:
    """Render searchable text summary for Cognee graph memory."""
    lines = [
        f"Composer Package: {meta.name} (Latest: {meta.latest_version})",
        f"Description: {meta.description}",
    ]
    if meta.maintainers:
        lines.append(f"Maintainers: {', '.join(meta.maintainers)}")
    if meta.abandoned:
        rep = meta.replacement_package or "no replacement specified"
        lines.append(f"ABANDONED UPSTREAM: Yes | Recommended Replacement Package: {rep}")
    if meta.versions:
        latest = meta.versions[0]
        if latest.php_constraint:
            lines.append(f"PHP Requirement: {latest.php_constraint}")
        if latest.require:
            reqs = ", ".join(f"{k}:{v}" for k, v in latest.require.items())
            lines.append(f"Requires: {reqs}")
    if meta.security_advisories:
        adv_strs = [
            f"{a.advisory_id} ({a.cve or 'no-cve'}, affected: {a.affected_versions}): {a.title}"
            for a in meta.security_advisories
        ]
        lines.append(f"Security Advisories: {'; '.join(adv_strs)}")
    return "\n".join(lines)


def sync_packagist_packages(
    selected_packages: list[str],
    package_payloads: dict[str, dict[str, Any]],
    advisories_payload: dict[str, Any] | None = None,
    changes_payload: dict[str, Any] | None = None,
    previous_state: dict[str, Any] | None = None,
    exclude_abandoned: bool = False,
    not_found_packages: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Synchronize Packagist packages incrementally using `/metadata/changes.json` cursor and tombstones.

    Emits `_deleted: True` tombstones when:
    1. `/metadata/changes.json` reports a `delete` action for a tracked package.
    2. `GET /packages/{vendor}/{package}.json` returns HTTP 404 (`not_found_packages`).
    3. A previously synced package is removed from `selected_packages`.
    4. `exclude_abandoned=True` and the package is marked `abandoned` upstream.

    Args:
        selected_packages: List of tracked `vendor/package` names.
        package_payloads: Mapping of `vendor/package` -> `{"api": ..., "p2": ...}` payloads.
        advisories_payload: Raw JSON dict from `POST /api/security-advisories/`.
        changes_payload: Raw JSON dict from `GET /metadata/changes.json?since=<cursor>`.
        previous_state: Dict with `{"cursor": int, "packages": dict[str, Any]}`.
        exclude_abandoned: If True, abandoned packages emit `_deleted: True` tombstones.
        not_found_packages: Optional set of `vendor/package` names that returned HTTP 404.

    Returns:
        Tuple of (emitted_documents: list[dict], updated_state: dict).
    """
    state = dict(previous_state or {})
    prev_cursor = int(state.get("cursor", 0) or 0)
    prev_packages: dict[str, Any] = dict(state.get("packages", {}))

    advisories_map = parse_security_advisories(advisories_payload or {})
    http_404_set = {p.lower() for p in (not_found_packages or set())}
    selected_normalized = [p.strip().lower() for p in selected_packages if p.strip()]
    selected_set = set(selected_normalized)

    updated_from_changes: set[str] | None = None
    deleted_from_changes: set[str] = set()
    new_cursor = prev_cursor

    if changes_payload is not None:
        parsed_cursor, actions = parse_metadata_changes(changes_payload)
        if parsed_cursor > 0:
            new_cursor = parsed_cursor
        if prev_cursor > 0:
            updated_from_changes = set()
            for act in actions:
                if act.action_type == "delete":
                    deleted_from_changes.add(act.package_name)
                elif act.action_type == "update":
                    updated_from_changes.add(act.package_name)
        else:
            for act in actions:
                if act.action_type == "delete":
                    deleted_from_changes.add(act.package_name)

    emitted_documents: list[dict[str, Any]] = []

    for pkg_name in selected_normalized:
        # 1. Check if deleted via changes.json or HTTP 404
        if pkg_name in deleted_from_changes or pkg_name in http_404_set:
            emitted_documents.append({
                "id": f"packagist:{pkg_name}",
                "name": pkg_name,
                "_deleted": True,
            })
            prev_packages.pop(pkg_name, None)
            continue

        # 2. If incremental cursor is active and package was already synced and not in update actions, skip
        if updated_from_changes is not None and pkg_name in prev_packages and pkg_name not in updated_from_changes:
            logger.debug(f"Skipping unchanged Packagist package {pkg_name} (cursor={prev_cursor})")
            continue

        raw_bundle = package_payloads.get(pkg_name, {})
        meta = parse_packagist_package(
            package_api_json=raw_bundle.get("api"),
            p2_metadata_json=raw_bundle.get("p2"),
            advisories=advisories_map.get(pkg_name, []),
        )

        # 3. Check if abandoned and user configured exclude_abandoned=True
        if exclude_abandoned and meta.abandoned:
            emitted_documents.append({
                "id": f"packagist:{pkg_name}",
                "name": pkg_name,
                "abandoned": True,
                "replacement_package": meta.replacement_package,
                "_deleted": True,
            })
            prev_packages.pop(pkg_name, None)
            continue

        doc: dict[str, Any] = {
            "id": f"packagist:{meta.name}",
            "name": meta.name,
            "description": meta.description,
            "repository": meta.repository,
            "maintainers": meta.maintainers,
            "abandoned": meta.abandoned,
            "replacement_package": meta.replacement_package,
            "downloads_total": meta.downloads_total,
            "favers": meta.favers,
            "latest_version": meta.latest_version,
            "versions": [asdict(v) for v in meta.versions],
            "security_advisories": [asdict(a) for a in meta.security_advisories],
            "text": _render_packagist_searchable_text(meta),
            "_deleted": False,
        }
        emitted_documents.append(doc)
        prev_packages[pkg_name] = {
            "latest_version": meta.latest_version,
            "abandoned": meta.abandoned,
            "advisory_ids": [a.advisory_id for a in meta.security_advisories],
        }

    # 4. Emit tombstones for deselected packages that were present in previous_state
    for prev_pkg in list(prev_packages.keys()):
        if prev_pkg not in selected_set:
            prev_packages.pop(prev_pkg, None)
            emitted_documents.append({
                "id": f"packagist:{prev_pkg}",
                "name": prev_pkg,
                "_deleted": True,
            })

    updated_state = {
        "cursor": new_cursor,
        "packages": prev_packages,
    }
    return emitted_documents, updated_state


def packagist_source(
    selected_packages: list[str],
    package_payloads: dict[str, dict[str, Any]],
    advisories_payload: dict[str, Any] | None = None,
    changes_payload: dict[str, Any] | None = None,
    previous_state: dict[str, Any] | None = None,
    exclude_abandoned: bool = False,
    not_found_packages: set[str] | None = None,
) -> Iterable[dict[str, Any]]:
    """Pulled document-path dlt source yielding Packagist package documents with _deleted tombstones."""
    docs, _ = sync_packagist_packages(
        selected_packages=selected_packages,
        package_payloads=package_payloads,
        advisories_payload=advisories_payload,
        changes_payload=changes_payload,
        previous_state=previous_state,
        exclude_abandoned=exclude_abandoned,
        not_found_packages=not_found_packages,
    )
    yield from docs


setattr(packagist_source, DOCUMENT_SOURCE_ATTR, True)
setattr(packagist_source, "write_disposition", "merge")
