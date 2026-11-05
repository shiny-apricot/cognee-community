# Cognee Community NuGet v3 Connector

A pulled `dlt` data-source connector for [Cognee](https://github.com/topoteretes/cognee) that ingests NuGet v3 (`.NET` / `C#`) package metadata, target-framework dependency groups, deprecation notices (with recommended replacement packages), and GitHub Security Advisories (`GHSA-*`) into graph memory.

## Features
- **Dynamic v3 Service Discovery**: Queries `index.json` (`https://api.nuget.org/v3/index.json` or private feeds) to resolve `RegistrationsBaseUrl/Versioned`, `SearchQueryService`, and `Catalog/3.0.0`.
- **Manifest & Filter Selection**: Select packages by ID list, search query, or directly from `.csproj`, `Directory.Packages.props`, or `packages.lock.json`.
- **Inline & Externalized Registration Pages**: Parses inline `catalogEntry` leaves and lazily fetches externalized registration page URLs (`@id`) only when `commitTimeStamp` changes.
- **Deprecation & Security Advisory Ingestion**: Captures `deprecation` notices (`reasons`, `message`, `alternatePackage.id` + version range) and `vulnerabilities` (`advisoryUrl`, `severity`).
- **Forget-on-Delete Tombstones**: Emits `_deleted: True` for unlisted versions (`listed: false`, `published: 1900-01-01T00:00:00+00:00`), deleted catalog packages (`nuget:PackageDelete`), and deselected packages.

## Installation

```bash
pip install cognee-community-connector-nuget
```

## Quickstart

```python
from cognee_community_connector_nuget import (
    discover_v3_endpoints,
    nuget_source,
    parse_project_manifest,
    sync_packages,
)

# 1. Parse tracked packages from Directory.Packages.props or .csproj
package_ids = parse_project_manifest(open("Directory.Packages.props").read(), "Directory.Packages.props")

# 2. Sync registration payloads with incremental state & tombstones
docs, state = sync_packages(registration_payloads, selected_package_ids=package_ids)
```
