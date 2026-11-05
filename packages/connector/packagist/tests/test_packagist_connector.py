"""Standalone Pytest Suite for Packagist / Composer Connector (#6483).

Covers Composer v2 minified metadata expansion (composer/2.0 + __unset),
composer.json and composer.lock manifest parsing, abandonment replacement notices,
PKSA security advisory linking, /metadata/changes.json high-resolution cursor
and ~dev suffix normalization, and forget-on-delete tombstones.
"""

import pytest

from cognee_community_connector_packagist import (
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

SAMPLE_P2_MONOLOG = {
    "minified": "composer/2.0",
    "packages": {
        "monolog/monolog": [
            {
                "name": "monolog/monolog",
                "description": "Sends your logs to files, sockets, inboxes, databases and various web services",
                "version": "3.5.0",
                "version_normalized": "3.5.0.0",
                "license": ["MIT"],
                "require": {"php": ">=8.1", "psr/log": "^2.0 || ^3.0"},
                "conflict": {"psr/log-implementation": "1.0.0"},
                "time": "2023-11-10T12:00:00+00:00"
            },
            {
                "version": "2.9.2",
                "version_normalized": "2.9.2.0",
                "require": {"php": ">=7.2", "psr/log": "^1.0.1 || ^2.0 || ^3.0"},
                "conflict": "__unset",
                "time": "2023-10-01T09:00:00+00:00"
            }
        ]
    }
}

SAMPLE_API_SWIFTMAILER_ABANDONED = {
    "package": {
        "name": "swiftmailer/swiftmailer",
        "description": "Swiftmailer, free feature-rich PHP mailer",
        "repository": "https://github.com/swiftmailer/swiftmailer",
        "maintainers": [{"name": "fabpot"}],
        "abandoned": "symfony/mailer",
        "downloads": {"total": 145000000},
        "favers": 9800,
        "versions": {
            "v6.3.0": {
                "version": "v6.3.0",
                "version_normalized": "6.3.0.0",
                "require": {"php": ">=7.0.0"},
                "license": ["MIT"],
                "abandoned": "symfony/mailer"
            }
        }
    }
}

SAMPLE_ADVISORIES = {
    "advisories": {
        "monolog/monolog": [
            {
                "advisoryId": "PKSA-dmw8-jd8k-q3c6",
                "packageName": "monolog/monolog",
                "title": "Header injection in NativeMailerHandler",
                "cve": "CVE-2021-21429",
                "affectedVersions": ">=1.0.0,<2.2.0",
                "link": "https://github.com/Seldaek/monolog/security/advisories/GHSA-5crp",
                "reportedAt": "2021-04-06T00:00:00+00:00"
            }
        ]
    }
}

SAMPLE_CHANGES_FEED = {
    "timestamp": 17934536320011,
    "actions": [
        {"type": "update", "package": "monolog/monolog~dev", "time": 1793453631},
        {"type": "delete", "package": "legacy/deleted-pkg", "time": 1793453632}
    ]
}


def test_expand_composer_v2_minified_versions_with_unset() -> None:
    """Verify Composer 2.0 minified metadata inherits prior keys and removes __unset keys."""
    expanded = expand_composer_v2_versions(SAMPLE_P2_MONOLOG, "monolog/monolog")
    assert len(expanded) == 2

    v1, v2 = expanded[0], expanded[1]
    assert v1["version"] == "3.5.0"
    assert v1["license"] == ["MIT"]
    assert "conflict" in v1

    # v2 inherits name, description, and license from v1, overrides version/require, and unsets conflict
    assert v2["name"] == "monolog/monolog"
    assert v2["description"].startswith("Sends your logs")
    assert v2["license"] == ["MIT"]
    assert v2["version"] == "2.9.2"
    assert v2["require"]["php"] == ">=7.2"
    assert "conflict" not in v2


def test_parse_composer_json_and_lock_manifests() -> None:
    """Verify extraction of vendor/package names from composer.json and composer.lock while excluding php/ext-*."""
    composer_json = {
        "require": {
            "php": "^8.2",
            "ext-json": "*",
            "monolog/monolog": "^3.5",
            "laravel/framework": "^11.0"
        },
        "require-dev": {
            "phpunit/phpunit": "^10.5"
        }
    }
    assert parse_composer_manifest(composer_json, include_dev=True) == [
        "laravel/framework",
        "monolog/monolog",
        "phpunit/phpunit",
    ]
    assert parse_composer_manifest(composer_json, include_dev=False) == [
        "laravel/framework",
        "monolog/monolog",
    ]

    composer_lock = {
        "packages": [{"name": "monolog/monolog"}, {"name": "psr/log"}],
        "packages-dev": [{"name": "mockery/mockery"}]
    }
    assert parse_composer_manifest(composer_lock, include_dev=True) == [
        "mockery/mockery",
        "monolog/monolog",
        "psr/log",
    ]


def test_parse_packagist_package_abandonment_and_metadata() -> None:
    """Verify parsing of maintainer abandonment notices (with replacement package and boolean true)."""
    meta = parse_packagist_package(package_api_json=SAMPLE_API_SWIFTMAILER_ABANDONED)
    assert meta.name == "swiftmailer/swiftmailer"
    assert meta.abandoned is True
    assert meta.replacement_package == "symfony/mailer"
    assert meta.downloads_total == 145000000
    assert meta.maintainers == ["fabpot"]

    # Also verify boolean abandoned=True when no replacement package is named
    bool_abandoned_api = {"package": {"name": "old/pkg", "abandoned": True}}
    meta_bool = parse_packagist_package(package_api_json=bool_abandoned_api)
    assert meta_bool.abandoned is True
    assert meta_bool.replacement_package is None


def test_parse_security_advisories_pksa_linking() -> None:
    """Verify parsing of PKSA security advisories and linking to package metadata."""
    adv_map = parse_security_advisories(SAMPLE_ADVISORIES)
    assert "monolog/monolog" in adv_map
    advs = adv_map["monolog/monolog"]
    assert len(advs) == 1
    assert advs[0].advisory_id == "PKSA-dmw8-jd8k-q3c6"
    assert advs[0].cve == "CVE-2021-21429"

    meta = parse_packagist_package(
        p2_metadata_json=SAMPLE_P2_MONOLOG,
        advisories=advs,
    )
    assert len(meta.security_advisories) == 1
    assert meta.versions[0].php_constraint == ">=8.1"


def test_parse_metadata_changes_cursor_and_dev_suffix_stripping() -> None:
    """Verify high-resolution timestamp cursor parsing and ~dev suffix stripping in changes.json."""
    cursor, actions = parse_metadata_changes(SAMPLE_CHANGES_FEED)
    assert cursor == 17934536320011
    assert len(actions) == 2
    assert actions[0].action_type == "update"
    assert actions[0].package_name == "monolog/monolog"
    assert actions[0].raw_package_field == "monolog/monolog~dev"
    assert actions[1].action_type == "delete"
    assert actions[1].package_name == "legacy/deleted-pkg"


def test_incremental_sync_skip_unchanged_and_advance_cursor() -> None:
    """Verify incremental sync uses changes.json cursor to skip unchanged packages and update changed ones."""
    payloads = {
        "monolog/monolog": {"p2": SAMPLE_P2_MONOLOG},
        "swiftmailer/swiftmailer": {"api": SAMPLE_API_SWIFTMAILER_ABANDONED},
    }
    docs, state = sync_packagist_packages(
        selected_packages=["monolog/monolog", "swiftmailer/swiftmailer"],
        package_payloads=payloads,
        advisories_payload=SAMPLE_ADVISORIES,
        changes_payload={"timestamp": 17934500000000, "actions": []},
    )
    assert len(docs) == 2
    assert state["cursor"] == 17934500000000
    assert "PKSA-dmw8-jd8k-q3c6" in docs[0]["text"]
    assert "symfony/mailer" in docs[1]["text"]

    # Second run: changes_payload only lists monolog/monolog~dev as updated; swiftmailer is skipped
    docs_inc, state_inc = sync_packagist_packages(
        selected_packages=["monolog/monolog", "swiftmailer/swiftmailer"],
        package_payloads=payloads,
        advisories_payload=SAMPLE_ADVISORIES,
        changes_payload=SAMPLE_CHANGES_FEED,
        previous_state=state,
    )
    assert len(docs_inc) == 1
    assert docs_inc[0]["name"] == "monolog/monolog"
    assert state_inc["cursor"] == 17934536320011


def test_forget_on_delete_404_deselected_and_exclude_abandoned_tombstones() -> None:
    """Verify _deleted tombstones on changes.json delete, HTTP 404, deselection, and exclude_abandoned=True."""
    payloads = {
        "monolog/monolog": {"p2": SAMPLE_P2_MONOLOG},
        "swiftmailer/swiftmailer": {"api": SAMPLE_API_SWIFTMAILER_ABANDONED},
    }
    # 1. exclude_abandoned=True emits _deleted: True for swiftmailer/swiftmailer
    docs_ab, state_ab = sync_packagist_packages(
        selected_packages=["monolog/monolog", "swiftmailer/swiftmailer"],
        package_payloads=payloads,
        exclude_abandoned=True,
    )
    swift_doc = next(d for d in docs_ab if d["name"] == "swiftmailer/swiftmailer")
    assert swift_doc["_deleted"] is True
    assert swift_doc["replacement_package"] == "symfony/mailer"

    # 2. HTTP 404 and deselection emit _deleted: True
    docs_del, _ = sync_packagist_packages(
        selected_packages=["missing/pkg-404"],
        package_payloads={},
        previous_state=state_ab,
        not_found_packages={"missing/pkg-404"},
    )
    deleted_names = {d["name"] for d in docs_del if d.get("_deleted") is True}
    assert "missing/pkg-404" in deleted_names
    assert "monolog/monolog" in deleted_names


def test_packagist_source_document_attr_contract() -> None:
    """Verify packagist_source carries DOCUMENT_SOURCE_ATTR, merge disposition, and compliant User-Agent."""
    headers = build_packagist_headers(bearer_token="priv_tok")
    assert "cognee-community-connector-packagist" in headers["User-Agent"]
    assert headers["Authorization"] == "Bearer priv_tok"

    assert getattr(packagist_source, DOCUMENT_SOURCE_ATTR, False) is True
    assert getattr(packagist_source, "write_disposition", "") == "merge"

    emitted = list(
        packagist_source(
            selected_packages=["swiftmailer/swiftmailer"],
            package_payloads={"swiftmailer/swiftmailer": {"api": SAMPLE_API_SWIFTMAILER_ABANDONED}},
        )
    )
    assert len(emitted) == 1
    assert emitted[0]["replacement_package"] == "symfony/mailer"
