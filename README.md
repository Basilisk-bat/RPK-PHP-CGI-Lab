# RPK PHP CGI Regression Lab

This public lab runs selected official PHP session-upload regression tests against PHP 8.5.11 and 8.5.12. It helps maintainers reproduce a narrow patched/reference difference and inspect the limits of that evidence. It is an early project; no broad adoption or production protection is claimed.

## Run it

- [`lab/windows/`](lab/windows/README.md) documents a Windows runner for locally downloaded, hash-checked PHP releases. It limits memory, process count and time, and saves receipts in an ignored local `runs/` directory.
- [The manual cloud workflow](.github/workflows/php-cgi-cloud-lab.yml) builds hash-checked official PHP source archives in GitHub Actions, then runs the selected tests in containers with networking disabled. See [`cloud/`](cloud/README.md) for limits and [the public comparison](cloud/RESULT-20261022.md) for a checked run.

The selected upstream fixtures and PHP's test runner are pinned by Git blob and SHA-256 in [`source-manifest.json`](lab/windows/source-manifest.json). The source files retain the bundled [PHP License](lab/windows/source/LICENSE); original lab code and documentation use [Apache License 2.0](LICENSE).

## What a result means

A selected pass or failure concerns fresh CGI processes in these fixtures. It does not demonstrate an exploit, cover every path in [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) or [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), test persistent workers, or prove that a serving application was updated. Run the lab only on local or explicitly owned systems. Its Windows runner does not enforce network or filesystem isolation.

PHP's [2026-10-21 release notice](https://www.php.net/archive/2026.php#2026-10-21-5) names the upstream fixed versions. Check the binary actually serving an owned application and its behavior after an owner-approved update.
