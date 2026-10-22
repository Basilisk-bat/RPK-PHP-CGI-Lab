# Windows CGI session regression lab

This lab runs three selected official PHP session-upload tests on fresh local CGI processes. It is for an owned Windows x64 host. The runner uses a Windows Job for a 256 MiB aggregate committed-memory limit, a 16-process limit, cleanup on job close, and a 90-second deadline. It refuses to start a new run when available physical memory is below 1024 MiB.

## Prepare the official runtimes

Install Python 3 and the Visual C++ runtime required by the official VS17 x64 PHP builds. From this directory, create `../php-patched-validation/`. Download these exact archives from the official PHP Windows archive into it:

| Runtime | Archive URL | Expected SHA-256 |
| --- | --- | --- |
| 8.5.12 NTS x64 | `https://downloads.php.net/~windows/releases/archives/php-8.5.12-nts-Win32-vs17-x64.zip` | `2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477` |
| 8.5.11 NTS x64 | `https://downloads.php.net/~windows/releases/archives/php-8.5.11-nts-Win32-vs17-x64.zip` | `0ea96e0d2b9b737a6036f05cf4e95c49313faa6d0f27bd97edb2742503f0c043` |

Extract 8.5.12 into `../php-patched-validation/runtime/` and 8.5.11 into `../php-patched-validation/runtime-reference-8.5.11/`. Do not place the downloaded archives or extracted runtimes in Git. The runner independently verifies each archive SHA-256 and every extracted file against the archive before it creates an event directory.

The selected upstream test sources and `run-tests.php` are in [`source/`](source/). Their exact upstream Git blob hashes and commit are in [`source-manifest.json`](source-manifest.json). The PHP source files retain their own [license](source/LICENSE).

## Run

From this directory:

```powershell
python .\run-cgi-regressions.py local-patched-20261022-1 --runtime-version 8.5.12
python .\run-cgi-regressions.py local-reference-20261022-1 --runtime-version 8.5.11 --allow-unpatched-reference
```

Replace the IDs for each new observation. A completed ID replays its saved receipt without executing PHP. A partial event directory must be reconciled before reuse. The older reference is explicitly opted in and its failing cases are recorded as a regression difference; they are not a successful defensive result.

The runner writes `runs/<event-id>/receipt.json`, JUnit XML, stdout and stderr. It checks that the run-local source copies match the verified source bytes just before launching PHP. The saved receipt records the exact selected tests, PHP runner exit, Job limits, peak memory, deadline and owned-process cleanup.

## Limits

The upstream `--offline` option narrows test selection; it is not network isolation. No OS network or filesystem sandbox is enforced here. These selected fresh-process CGI tests do not establish PHP-FPM, Apache, persistent-worker, full CVE, exploit or deployed-service behavior. A new release, source revision or test selection needs its own reviewed hashes and event IDs.
