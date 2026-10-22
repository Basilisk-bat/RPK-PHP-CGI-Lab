# RPK PHP CGI Regression Lab

This public lab runs selected official PHP session-upload regression tests against PHP 8.5.11 and 8.5.12. It helps maintainers reproduce a narrow patched/reference difference and inspect the limits of that evidence. It does not scan or repair a website.

## Start here

**No local setup:** [Follow the hosted guide](cloud/QUICKSTART.md). GitHub Actions builds the pinned PHP source archives and runs the tests in bounded containers. You need a GitHub account and your own fork; you do not need PHP, Python, Docker, or a website address.

**Windows x64, local:** Download this repository as a ZIP, extract it into a folder you can write to, and double-click [`Start-Lab.cmd`](Start-Lab.cmd). Choose the patched check. The launcher asks before downloading pinned official PHP and portable Python archives, checks their hashes and extracted bytes, and saves a plain-language local HTML report. It does not install PHP or Python system-wide. Allow about 200 MiB of local files and have at least 1 GiB of available memory and free disk space. The [Windows guide](lab/windows/README.md) covers the optional older reference, failures, raw receipts and limits. **This local path has no OS network or filesystem sandbox.** Use the hosted path if local isolation matters.

Both paths run the same selected upstream fixtures. [The public cloud comparison](cloud/RESULT-20261022.md) records checked runs and their exact tested commits. A later source or workflow change needs its own run; a documentation change is not a new experiment.

For errors, use [troubleshooting](docs/TROUBLESHOOTING.md). The [security scope](SECURITY.md) explains what the execution bounds do and where trust remains. The [engine proposal audit](docs/ENGINE-AUDIT.md) records measured decisions about stronger isolation and crash telemetry.

The selected upstream fixtures and PHP's test runner are pinned by Git blob and SHA-256 in [`source-manifest.json`](lab/windows/source-manifest.json). The source files retain the bundled [PHP License](lab/windows/source/LICENSE); original lab code and documentation use [Apache License 2.0](LICENSE).

## Read the result

Open `report.html` from a local run or downloaded cloud artifact. A patched pass means the three selected cases passed in that PHP release. The older reference is intentionally unpatched; its three failures can confirm the selected difference. A stopped run, missing artifact, or unchecked boundary establishes no comparison. Keep raw local receipts private when they contain machine paths.

## What a result means

A selected pass or failure concerns fresh CGI processes in these fixtures. It does not demonstrate an exploit, cover every path in [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) or [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), test persistent workers, or prove that a serving application was updated. Run the lab only on local or explicitly owned systems. Its Windows runner does not enforce network or filesystem isolation.

PHP's [2026-10-21 release notice](https://www.php.net/archive/2026.php#2026-10-21-5) names the upstream fixed versions. Check the binary actually serving an owned application and its behavior after an owner-approved update.
