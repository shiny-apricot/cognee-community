"""Standalone Pytest Suite for NuGet v3 Connector (#6485).

Covers service discovery, auth headers, .csproj/Directory.Packages.props/packages.lock.json parsing,
inline and externalized registration pages, deprecation notices, vulnerability advisories,
incremental sync state skipping, and unlisted/deselected/deleted _deleted tombstones.
"""

import json
import pytest

from cognee_community_connector_nuget import (
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

SAMPLE_SERVICE_INDEX = {
    "version": "3.0.0",
    "resources": [
        {
            "@id": "https://api.nuget.org/v3/registration5-gz-semver2/",
            "@type": "RegistrationsBaseUrl/Versioned",
            "comment": "Base URL of Azure storage where NuGet package registration info is stored"
        },
        {
            "@id": "https://azuresearch-usnc.nuget.org/query",
            "@type": "SearchQueryService",
            "comment": "Query endpoint of search service (primary)"
        },
        {
            "@id": "https://api.nuget.org/v3/catalog0/index.json",
            "@type": "Catalog/3.0.0",
            "comment": "Index of the NuGet package catalog"
        }
    ]
}

SAMPLE_REGISTRATION_DATA = {
    "commitId": "b8a8b845-8f6a-4b09-a764-159c5d15a5f1",
    "commitTimeStamp": "2026-10-15T12:00:00Z",
    "count": 1,
    "items": [
        {
            "count": 2,
            "items": [
                {
                    "catalogEntry": {
                        "id": "Newtonsoft.Json",
                        "version": "12.0.1",
                        "description": "Json.NET is a popular high-performance JSON framework for .NET",
                        "authors": "James Newton-King",
                        "published": "2018-11-27T10:00:00Z",
                        "listed": True,
                        "licenseExpression": "MIT",
                        "dependencyGroups": [
                            {
                                "targetFramework": ".NETStandard2.0",
                                "dependencies": [
                                    {"id": "Microsoft.CSharp", "range": "[4.5.0, )"}
                                ]
                            }
                        ],
                        "vulnerabilities": [
                            {
                                "advisoryUrl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr",
                                "severity": "2"
                            }
                        ]
                    }
                },
                {
                    "catalogEntry": {
                        "id": "Newtonsoft.Json",
                        "version": "12.0.2-beta1",
                        "description": "Unlisted pre-release build",
                        "authors": "James Newton-King",
                        "published": "1900-01-01T00:00:00+00:00",
                        "listed": False,
                        "dependencyGroups": []
                    }
                }
            ]
        }
    ]
}

SAMPLE_DEPRECATED_PACKAGE = {
    "commitId": "c9b9c9-legacy-commit",
    "commitTimeStamp": "2026-10-16T14:30:00Z",
    "count": 1,
    "items": [
        {
            "items": [
                {
                    "catalogEntry": {
                        "id": "WindowsAzure.Storage",
                        "version": "9.3.3",
                        "description": "Client library for Azure Storage",
                        "published": "2018-08-01T12:00:00Z",
                        "listed": True,
                        "deprecation": {
                            "message": "This library has been replaced by Azure.Storage.Blobs.",
                            "reasons": ["Legacy"],
                            "alternatePackage": {
                                "id": "Azure.Storage.Blobs",
                                "range": "[12.0.0, )"
                            }
                        }
                    }
                }
            ]
        }
    ]
}


def test_discover_v3_endpoints() -> None:
    """Verify dynamic discovery of registration, search, and catalog URLs from index.json."""
    endpoints = discover_v3_endpoints(SAMPLE_SERVICE_INDEX)
    assert endpoints.registration_base_url == "https://api.nuget.org/v3/registration5-gz-semver2/"
    assert endpoints.search_service_url == "https://azuresearch-usnc.nuget.org/query"
    assert endpoints.catalog_url == "https://api.nuget.org/v3/catalog0/index.json"


def test_build_nuget_auth_headers() -> None:
    """Verify API key, Bearer, and Basic authentication header construction for private feeds."""
    h_api = build_nuget_auth_headers(api_key="secret-nuget-key")
    assert h_api["X-NuGet-ApiKey"] == "secret-nuget-key"

    h_bearer = build_nuget_auth_headers(bearer_token="ghp_token123")
    assert h_bearer["Authorization"] == "Bearer ghp_token123"

    h_basic = build_nuget_auth_headers(basic_username="dev", basic_password="pw")
    assert h_basic["Authorization"].startswith("Basic ")


def test_parse_project_manifest_csproj_and_props_and_lock() -> None:
    """Verify package ID extraction from .csproj, Directory.Packages.props, and packages.lock.json."""
    csproj = """
    <Project Sdk="Microsoft.NET.Sdk">
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageReference Include="Serilog" Version="3.1.1" />
      </ItemGroup>
    </Project>
    """
    assert parse_project_manifest(csproj, "App.csproj") == ["Newtonsoft.Json", "Serilog"]

    props = """
    <Project>
      <ItemGroup>
        <PackageVersion Include="Azure.Storage.Blobs" Version="12.19.1" />
      </ItemGroup>
    </Project>
    """
    assert parse_project_manifest(props, "Directory.Packages.props") == ["Azure.Storage.Blobs"]

    lock_json = json.dumps({
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Polly": {"type": "Direct", "resolved": "8.2.0"},
                "Dapper": {"type": "Transitive", "resolved": "2.1.28"}
            }
        }
    })
    assert parse_project_manifest(lock_json, "packages.lock.json") == ["Dapper", "Polly"]


def test_parse_registration_index_vulnerabilities() -> None:
    """Verify parsing of package versions, target-framework dependencies, and security vulnerabilities."""
    meta = parse_registration_index(SAMPLE_REGISTRATION_DATA)
    assert meta.package_id == "Newtonsoft.Json"
    assert meta.commit_id == "b8a8b845-8f6a-4b09-a764-159c5d15a5f1"
    assert len(meta.versions) == 2

    v1 = meta.versions[0]
    assert v1.version == "12.0.1"
    assert v1.listed is True
    assert v1.is_deleted_tombstone is False
    assert ".NETStandard2.0" in v1.dependency_groups
    assert len(v1.vulnerabilities) == 1
    assert v1.vulnerabilities[0].severity == "2"
    assert "GHSA-5crp-9r3c-p9vr" in v1.vulnerabilities[0].advisory_url


def test_externalized_registration_page_fetching() -> None:
    """Verify externalized registration pages (@id without inline items) are resolved on demand."""
    external_index = {
        "commitId": "ext-commit-1",
        "commitTimeStamp": "2026-10-18T00:00:00Z",
        "count": 1,
        "items": [
            {
                "@id": "https://api.nuget.org/v3/registration5-gz-semver2/serilog/page/1.0.0/3.1.1.json",
                "commitTimeStamp": "2026-10-18T00:00:00Z",
                "lower": "1.0.0",
                "upper": "3.1.1"
            }
        ]
    }
    external_page_payload = {
        "items": [
            {
                "catalogEntry": {
                    "id": "Serilog",
                    "version": "3.1.1",
                    "description": "Simple .NET logging with fully-structured events",
                    "published": "2023-11-01T00:00:00Z",
                    "listed": True
                }
            }
        ]
    }
    fetched_urls: list[str] = []

    def fake_fetcher(url: str) -> dict:
        fetched_urls.append(url)
        return external_page_payload

    meta = parse_registration_index(external_index, page_fetcher=fake_fetcher)
    assert len(fetched_urls) == 1
    assert meta.package_id == "Serilog"
    assert meta.latest_version == "3.1.1"


def test_unlisted_version_tombstone() -> None:
    """Verify that unlisted versions (published=1900-01-01 or listed=False) emit deleted tombstones."""
    meta = parse_registration_index(SAMPLE_REGISTRATION_DATA, include_unlisted=False)
    v2 = meta.versions[1]
    assert v2.version == "12.0.2-beta1"
    assert v2.listed is False
    assert v2.is_deleted_tombstone is True


def test_deprecation_metadata_parsing() -> None:
    """Verify structured deprecation reasons and recommended replacement packages."""
    meta = parse_registration_index(SAMPLE_DEPRECATED_PACKAGE)
    assert len(meta.versions) == 1
    v = meta.versions[0]
    assert v.deprecation is not None
    assert "Legacy" in v.deprecation.reasons
    assert v.deprecation.alternate_package_id == "Azure.Storage.Blobs"
    assert "[12.0.0, )" in (v.deprecation.alternate_package_range or "")


def test_incremental_sync_deselected_and_state_tombstones() -> None:
    """Verify incremental sync skips unchanged commits and emits _deleted tombstones on deselection."""
    docs, state = sync_packages([SAMPLE_REGISTRATION_DATA, SAMPLE_DEPRECATED_PACKAGE])
    assert len(docs) == 3
    assert docs[0]["_deleted"] is False
    assert docs[1]["_deleted"] is True
    assert "GHSA-5crp-9r3c-p9vr" in docs[0]["text"]
    assert "Azure.Storage.Blobs" in docs[2]["text"]

    # Subsequent run with identical commitTimeStamp should skip emitting documents
    docs_cached, state_cached = sync_packages(
        [SAMPLE_REGISTRATION_DATA, SAMPLE_DEPRECATED_PACKAGE],
        previous_state=state,
    )
    assert len(docs_cached) == 0

    # Deselecting WindowsAzure.Storage emits a _deleted tombstone and prunes state
    docs_deselected, state_after = sync_packages(
        [SAMPLE_REGISTRATION_DATA],
        previous_state=state_cached,
        selected_package_ids=["Newtonsoft.Json"],
    )
    assert len(docs_deselected) == 1
    assert docs_deselected[0]["package_id"] == "WindowsAzure.Storage"
    assert docs_deselected[0]["_deleted"] is True
    assert "WindowsAzure.Storage" not in state_after


def test_nuget_source_document_attr_contract() -> None:
    """Verify nuget_source carries DOCUMENT_SOURCE_ATTR and merge write_disposition."""
    assert getattr(nuget_source, DOCUMENT_SOURCE_ATTR, False) is True
    assert getattr(nuget_source, "write_disposition", "") == "merge"
    emitted = list(nuget_source([SAMPLE_DEPRECATED_PACKAGE]))
    assert len(emitted) == 1
    assert emitted[0]["package_id"] == "WindowsAzure.Storage"
