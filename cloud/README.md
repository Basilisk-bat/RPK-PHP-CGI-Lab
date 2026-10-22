# Cloud PHP CGI experiment

For a first run without local tools, use the [hosted quickstart](QUICKSTART.md). Each job's GitHub summary and downloaded `report.html` explain its selected result in ordinary language; `summary.json` and the steps below provide the technical evidence.

The [GitHub Actions workflow](../.github/workflows/php-cgi-cloud-lab.yml) runs only by manual dispatch. It downloads official PHP 8.5.11 and 8.5.12 source archives, checks pinned SHA-256 values, builds each version, verifies the selected upstream source files, and runs three CGI regression fixtures. The result check compares their in-container hashes with the pinned source manifest and checks both PHP version banners. The GitHub checkout and artifact actions are pinned to reviewed commits. Each run ID, attempt and PHP version names a new event.

Build steps need network access for source archives and Ubuntu packages. The test container uses `--network none`, a read-only root, a non-root user, no added capabilities, a 512 MiB memory limit, a 64-process limit and no new privileges. Its writable `/work` and `/tmp` tmpfs mounts request `noexec`, `nosuid` and `nodev`, and the runner disables core dumps. The host checks Docker's final configuration and exit status before it accepts a selected result. These controls apply to the test container, not the whole GitHub runner.

The only host directory writable by the container is its dedicated guest result directory; it also has private writable `/work` and `/tmp` areas. Host-generated metadata and verified copies of bounded guest files stay in a sibling host directory. The workflow requires an artifact upload for a green job and also prints size-limited, hashed evidence records to the job log. Neither route guarantees long-term retention. Review each run and reconstruct the log records with `verify_log_evidence.py` before citing a result:

```text
python3 cloud/verify_log_evidence.py --log JOB_LOG.txt --run-id RUN_ID --attempt ATTEMPT --job-id JOB_ID --repository OWNER/REPO --version 8.5.12 --commit FULL_SHA --output NEW_OUTPUT_DIR
```

`RUN_ID` and `ATTEMPT` are on the GitHub run page or in its URL and attempt selector. Open the PHP version's job; its URL ends in `job/JOB_ID`. The full commit SHA appears on the run page. Use the job's **Download log archive** control to obtain `JOB_LOG.txt`; extract and select that exact job's text log. `OWNER/REPO` names your fork. Use a fresh output directory per job, and repeat with the other version and job ID. The verifier rejects missing, repeated, reordered or mismatched log records and checks the bounded file hashes. A log from a different repository, commit, run, attempt or job is not interchangeable. The log record itself does not contain GitHub's job ID, so bind that ID by selecting the job's downloaded log from the run UI.

The selected older reference suite is expected to show the regression difference, but its failure remains a failed test suite. An absent result, unexpected exit, boundary mismatch or incomplete log evidence remains unverified. These tests do not deploy PHP, establish persistent-worker behavior, prove a working exploit or validate a live service.
