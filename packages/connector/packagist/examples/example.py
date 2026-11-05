"""Runnable example for Cognee Community Packagist / Composer Connector."""

from cognee_community_connector_packagist import (
    parse_composer_manifest,
    sync_packagist_packages,
)


def main() -> None:
    composer_json = {
        "require": {
            "php": ">=8.2",
            "monolog/monolog": "^3.5",
            "swiftmailer/swiftmailer": "^6.3",
        }
    }
    selected = parse_composer_manifest(composer_json)
    print(f"Selected Composer packages: {selected}")

    payloads = {
        "monolog/monolog": {
            "api": {
                "package": {
                    "name": "monolog/monolog",
                    "description": "Sends your logs to files, sockets, inboxes, databases and various web services",
                    "maintainers": [{"name": "Seldaek"}],
                    "abandoned": False,
                }
            },
            "p2": {
                "minified": "composer/2.0",
                "packages": {
                    "monolog/monolog": [
                        {"name": "monolog/monolog", "version": "3.5.0", "require": {"php": ">=8.1"}},
                        {"version": "3.4.0"},
                    ]
                },
            },
        },
        "swiftmailer/swiftmailer": {
            "api": {
                "package": {
                    "name": "swiftmailer/swiftmailer",
                    "description": "Swiftmailer, free feature-rich PHP mailer",
                    "abandoned": "symfony/mailer",
                }
            }
        },
    }
    advisories = {
        "advisories": {
            "monolog/monolog": [
                {
                    "advisoryId": "PKSA-dmw8-jd8k-q3c6",
                    "title": "Remote code execution in NativeMailerHandler",
                    "cve": "CVE-2021-21429",
                    "affectedVersions": ">=1.0.0,<2.2.0",
                    "link": "https://github.com/Seldaek/monolog/security/advisories/GHSA-...",
                    "reportedAt": "2021-04-06T00:00:00+00:00",
                }
            ]
        }
    }

    docs, state = sync_packagist_packages(
        selected_packages=selected,
        package_payloads=payloads,
        advisories_payload=advisories,
    )
    for doc in docs:
        print(f"Synced: {doc['id']} | Abandoned: {doc.get('abandoned')} -> {doc.get('replacement_package')}")


if __name__ == "__main__":
    main()
