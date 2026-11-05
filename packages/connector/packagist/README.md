# Cognee Community Packagist / Composer Connector

A pulled `dlt` data-source connector for [Cognee](https://github.com/topoteretes/cognee) that ingests PHP / Composer package metadata from [Packagist](https://packagist.org) (`repo.packagist.org/p2/` and `packagist.org`), including Composer v2 minified release records, maintainer abandonment notices (with recommended replacement packages), and Packagist security advisories (`PKSA-*`).

## Features
- **Composer v2 Minified Metadata Expansion**: Expands `composer/2.0` minified release streams from `https://repo.packagist.org/p2/{vendor}/{package}.json` (including `__unset` key pruning).
- **Manifest & Vendor Selection**: Select packages by `vendor/package` list, vendor prefix, or directly from `composer.json` and `composer.lock`.
- **Abandonment & Security Advisory Linking**: Ingests upstream `abandoned` flags and replacement package recommendations (e.g., `swiftmailer/swiftmailer` -> `symfony/mailer`) alongside `POST /api/security-advisories/` (`PKSA-*`, `cve`, `affectedVersions`).
- **Incremental Sync via `/metadata/changes.json`**: Tracks Packagist's high-resolution 10,000th-of-a-second `timestamp` cursor (`GET /metadata/changes.json?since=<cursor>`), stripping `~dev` suffixes and skipping unchanged packages.
- **Forget-on-Delete Tombstones**: Emits `_deleted: True` rows when `/metadata/changes.json` reports a `delete` action, when `GET /packages/{vendor}/{package}.json` returns HTTP 404, when a package is deselected, or when `exclude_abandoned=True`.

## Installation

```bash
pip install cognee-community-connector-packagist
```

## Quickstart

```python
from cognee_community_connector_packagist import (
    packagist_source,
    parse_composer_manifest,
    sync_packagist_packages,
)

# 1. Extract packages from composer.json or composer.lock
selected = parse_composer_manifest(open("composer.lock").read())

# 2. Run incremental sync with Packagist changes.json cursor and advisories
docs, state = sync_packagist_packages(
    selected_packages=selected,
    package_payloads=fetched_payloads,
    advisories_payload=advisories_json,
    changes_payload=changes_json,
)
```
