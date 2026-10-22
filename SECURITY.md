# Security and scope

This repository is a defensive PHP CGI regression lab. It runs its included, pinned tests against local downloaded PHP runtimes or against PHP built in GitHub Actions. It does not test arbitrary websites, accept target URLs, install a production PHP update, or prove that a website is protected.

## Boundaries

- The Windows launcher verifies official archive hashes and extracted bytes, then runs selected fixtures under a Windows Job with a memory, process and elapsed-time bound. It has **no OS network or filesystem sandbox**. Use it only on a system you own or administer, and keep local `runs/` receipts private; they can contain machine paths.
- The GitHub Actions build host has network access to fetch source archives and packages. The later test container requests no network, a read-only root, non-root UID/GID, no added capabilities, no new privileges, bounded memory and processes, and restricted writable mounts. Host-side metadata checks the requested container configuration and its exit. The GitHub runner, Docker daemon, kernel, base image and package repositories remain trusted components.
- A green cloud job means the selected comparison and artifact upload completed under the checked conditions. A green hosted Windows bootstrap job means the patched local checks and sanitized packet upload completed on that runner image. Neither establishes complete CVE coverage, exploitability, a bit-for-bit reproducible build, a bare-machine Windows setup, or a deployed-service repair.

## Report a problem

For a suspected security problem in the lab, use this repository's **Security** tab and private vulnerability reporting when that control is available. If it is unavailable, open a minimal public issue requesting a private contact route. Do not post credentials, private paths, target data or exploit details in a public issue.

For ordinary setup failures, include the path chosen (hosted or local), the step that stopped, and a redacted error message. Do not upload a raw local receipt until you have reviewed its paths and environment fields.
