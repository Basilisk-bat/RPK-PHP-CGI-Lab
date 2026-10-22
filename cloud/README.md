# Cloud PHP CGI experiment

The [GitHub Actions workflow](../.github/workflows/php-cgi-cloud-lab.yml) runs only by manual dispatch. It downloads official PHP 8.5.11 and 8.5.12 source archives, checks pinned SHA-256 values, builds each version, verifies the selected upstream source files, and runs three CGI regression fixtures. Each run ID, attempt and PHP version names a new event.

Build steps need network access for source archives and Ubuntu packages. The test container uses `--network none`, a read-only root, a non-root user, no added capabilities, a 512 MiB memory limit, a 64-process limit and no new privileges. The host checks Docker's final configuration and exit status before it accepts a selected result. These controls apply to the test container, not the whole GitHub runner.

The only host directory writable by the container is its dedicated guest result directory; it also has private writable `/work` and `/tmp` areas. Host-generated metadata and verified copies of bounded guest files stay in a sibling host directory. The workflow attempts an artifact upload and also prints size-limited, hashed evidence records to the job log. Neither route guarantees long-term retention. Review each run and reconstruct the log records with `verify_log_evidence.py` before citing a result:

```text
python3 cloud/verify_log_evidence.py --log JOB_LOG.txt --run-id RUN_ID --attempt ATTEMPT --job-id JOB_ID --repository OWNER/REPO --version 8.5.12 --commit FULL_SHA --output NEW_OUTPUT_DIR
```

The selected older reference suite is expected to show the regression difference, but its failure remains a failed test suite. An absent result, unexpected exit, boundary mismatch or incomplete log evidence remains unverified. These tests do not deploy PHP, establish persistent-worker behavior, prove a working exploit or validate a live service.
