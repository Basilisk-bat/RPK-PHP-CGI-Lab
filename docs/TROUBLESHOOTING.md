# Troubleshooting the PHP CGI lab

Start with the [hosted quickstart](../cloud/QUICKSTART.md) or [Windows local guide](../lab/windows/README.md). The lab does not need a website address.

| Symptom | What it means | Next action |
| --- | --- | --- |
| The local launcher says less than 1 GiB of RAM or disk is free | Its preflight stopped before starting a new PHP test. | Make space using your normal device controls, then launch again. Do not change the guard to force a run. |
| Official archive download fails | This version's runtime was not ready. A temporary partial download is discarded. | Check access to the official Python or PHP site and retry. The launcher asks again before downloading. |
| A cached archive fails SHA-256 or extracted files differ | The files no longer match the reviewed archive. The rejected cache is left in place. | Preserve or inspect that exact folder; remove or move it only after deciding it is safe, then let the launcher fetch a fresh copy. Do not skip verification. |
| Windows reports a missing `VCRUNTIME` DLL | The official PHP or Python binary may need the x64 Microsoft Visual C++ runtime. | Follow [Microsoft's supported x64 redistributable guide](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist/), then start a fresh event. The launcher never installs it for you. |
| A run folder exists but has no accepted receipt | The observation stopped after creating its event directory. | Keep the partial folder, read `stdout.txt` and `stderr.txt` if present, correct the cause, and start a fresh event. Never relabel the partial run as a pass. |
| Reusing an event ID exits 2 | The saved receipt is historical and PHP was not run again. | Read that receipt for history; use a fresh ID to make a new observation. The guided launcher creates fresh IDs automatically. |
| The older PHP job shows three failed tests but the cloud job is green | The checker accepted the selected patched/reference difference. | Read both `report.html` files and their `summary.json` values. The older release is not considered protected. |
| A cloud job fails or its artifact is missing | The result or saved evidence is incomplete. | Open the failing GitHub step. Keep its run URL and commit; do not cite it as a completed comparison. A maintainer can inspect the bounded job-log evidence. |
| Your organization blocks local scripts or executables | Local execution is not an available route under that policy. | Use the hosted guide; do not weaken the organization's rule for the lab. |

For a support issue, share the GitHub run URL or a redacted error. Raw local receipts can include machine paths and environment details; review them before sharing.
