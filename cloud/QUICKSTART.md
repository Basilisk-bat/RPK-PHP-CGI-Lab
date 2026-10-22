# Run the PHP comparison on GitHub

This lab compares its included test cases on PHP 8.5.12 and 8.5.11. GitHub runs the experiment for you; this route does not require installing PHP, Python or Docker on your computer. It does not scan or repair your website.

## Create a copy you can run

Sign in to GitHub and open [RPK-PHP-CGI-Lab](https://github.com/Basilisk-bat/RPK-PHP-CGI-Lab). Select **Fork**, choose your account as the owner, and select **Create fork**. A fork is your copy of the public project. [GitHub's fork instructions](https://docs.github.com/en/pull-requests/how-tos/work-with-forks/fork-a-repo) explain the controls.

Open the **Actions** tab in your copy. If GitHub asks you to enable workflows, enable them there. Forked repositories need Actions enabled before their workflows can run. [GitHub's workflow documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflows-in-forked-repositories)

Your public fork and its results are public. This experiment uses the lab's supplied files; it does not need passwords, API keys, private files or website addresses.

## Start the experiment

In **Actions**, select **PHP CGI cloud lab**. Select **Run workflow**, choose **main**, then confirm **Run workflow**. Open the new run when it appears. If the button is missing, check that you are in your copy, Actions is enabled, and you have write access. [GitHub's manual-run instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

The run builds both PHP versions before testing them, so it takes several minutes. If you are unsure whether your click started a run, check the run list before starting another. A new run is a new experiment with its own evidence.

Open each PHP job to see progress. A failed download, build, timeout or evidence check means that experiment did not establish the expected comparison. A green workflow means its automated steps accepted the comparison; it does not mean your computer or website is secure.

## Read and keep the result

After the run finishes, read the plain-language PHP job summaries on its run page. In **Artifacts**, download the result ZIP for each PHP version and extract them into separate folders. GitHub requires you to be signed in and have read access to download artifacts. [GitHub's artifact-download instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)

Open `report.html` in each extracted folder. It explains the selected result and its limit without requiring you to read JSON. The two reports should say **Selected patched checks passed** for PHP 8.5.12 and **Older reference showed the selected difference** for PHP 8.5.11. If either report says **No verified comparison**, do not cite that run as a verified comparison.

For a technical check, open `summary.json` from each extracted folder in a text editor. For a new run of the current checker, the recorded result should be:

| Field | PHP 8.5.12 | PHP 8.5.11 reference |
| --- | --- | --- |
| `version` | `8.5.12` | `8.5.11` |
| `passed` | 3 | 0 |
| `failed` | 0 | 3 |
| `dockerWaitExit` and `containerExitCode` | 0 | 1 |
| `boundaryVerified`, `selectedIdentityMatch`, `fixtureHashesVerified`, `runtimeVersionVerified`, `exitVerified`, `selectedOutcomeVerified` | All `true` | All `true` |

The reference deliberately runs the older PHP version. Its failing test cases show the selected difference from the patched version. They are not evidence that the older version is protected. The reference job can be green because its checker confirmed the intended comparison while recording that the PHP tests failed.

Missing files, missing fields, a `false` check, or different counts mean the comparison needs review. Reading these fields is an overview, not independent verification that the downloaded files are authentic. Keep the ZIPs together with the run's web address and commit. The workflow requests 14-day artifact retention; download availability can end earlier if the repository owner deletes the run or artifact. The [technical evidence guide](README.md) explains the separate job-log verification route.

If artifacts are missing, open the **Save bounded run evidence** step to inspect its error. The current workflow fails the job when that upload fails or has no files. Do not describe an unavailable ZIP as saved successfully. Share the run address with the maintainer so the recorded job logs can be checked.

These results cover the included fresh CGI test processes. They do not prove every PHP security issue is fixed, test a long-running web server, or verify that a real website uses the patched version.
