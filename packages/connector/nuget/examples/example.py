"""Runnable example for Cognee Community NuGet v3 Connector."""

from cognee_community_connector_nuget import (
    discover_v3_endpoints,
    parse_project_manifest,
    sync_packages,
)


def main() -> None:
    sample_index = {
        "version": "3.0.0",
        "resources": [
            {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/Versioned"},
            {"@id": "https://azuresearch-usnc.nuget.org/query", "@type": "SearchQueryService"},
            {"@id": "https://api.nuget.org/v3/catalog0/index.json", "@type": "Catalog/3.0.0"},
        ],
    }
    endpoints = discover_v3_endpoints(sample_index)
    print(f"Resolved Registration Endpoint: {endpoints.registration_base_url}")

    csproj_xml = """
    <Project Sdk="Microsoft.NET.Sdk">
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageReference Include="WindowsAzure.Storage" Version="9.3.3" />
      </ItemGroup>
    </Project>
    """
    selected_ids = parse_project_manifest(csproj_xml, "MyService.csproj")
    print(f"Selected Packages from .csproj: {selected_ids}")

    sample_registration = {
        "commitId": "b8a8b845-8f6a-4b09-a764-159c5d15a5f1",
        "commitTimeStamp": "2026-10-15T12:00:00Z",
        "items": [
            {
                "items": [
                    {
                        "catalogEntry": {
                            "id": "WindowsAzure.Storage",
                            "version": "9.3.3",
                            "description": "Legacy Azure Storage SDK",
                            "published": "2018-08-01T12:00:00Z",
                            "listed": True,
                            "deprecation": {
                                "reasons": ["Legacy"],
                                "message": "Use Azure.Storage.Blobs instead.",
                                "alternatePackage": {"id": "Azure.Storage.Blobs", "range": "[12.0.0, )"},
                            },
                        }
                    }
                ]
            }
        ],
    }
    docs, state = sync_packages([sample_registration], selected_package_ids=selected_ids)
    for doc in docs:
        print(f"Synced Document: {doc['id']} | Deleted: {doc['_deleted']}")


if __name__ == "__main__":
    main()
