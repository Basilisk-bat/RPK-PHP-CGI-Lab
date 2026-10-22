[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:GITHUB_EVENT_PATH -or
    -not $env:GITHUB_REPOSITORY -or -not $env:GITHUB_RUN_ID) {
    throw 'Hosted bootstrap packets are generated only inside a GitHub Actions run.'
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'A hosted bootstrap packet already exists at the requested output path.'
}
$run = (Resolve-Path -LiteralPath $RunDirectory).Path
$receiptPath = Join-Path $run 'receipt.json'
$junitPath = Join-Path $run 'junit.xml'
$reportPath = Join-Path $run 'report.html'
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$expected = @(
    'ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt',
    'ext/session/tests/rfc1867_no_user_code.phpt',
    'ext/session/tests/rfc1867_sid_invalid.phpt'
)
$cases = @($receipt.testCases)
if ($receipt.runId -ne (Split-Path -Leaf $run) -or $receipt.runtimeVersion -ne '8.5.12' -or
    $receipt.exitCode -ne 0 -or $receipt.selectedTestsPassed -ne $true -or
    $receipt.selectedIdentityMatch -ne $true -or $receipt.deadlineExceeded -ne $false -or
    $receipt.activeProcessesAfterCleanup -ne 0 -or $receipt.jobLimitsReadbackVerified -ne $true -or
    $receipt.harnessError -or $receipt.junitParseError -or $cases.Count -ne $expected.Count -or
    @($cases | Where-Object { $_.relativePath -notin $expected -or
        $_.failures -ne 0 -or $_.errors -ne 0 -or $_.skips -ne 0 -or $_.warnings -ne 0 }).Count -ne 0 -or
    @($cases | Select-Object -ExpandProperty relativePath -Unique).Count -ne $expected.Count) {
    throw 'Hosted receipt failed selected identity, result, bounds or cleanup checks.'
}

$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.Load($junitPath)
$suites = $xml.SelectNodes('/testsuites/testsuite')
$nodes = $xml.SelectNodes('/testsuites/testsuite/testcase')
if ($suites.Count -ne 1 -or $nodes.Count -ne $expected.Count -or
    $xml.DocumentElement.GetAttribute('failures') -ne '0' -or
    $xml.DocumentElement.GetAttribute('errors') -ne '0') {
    throw 'Actual JUnit shape or outcome differs from the receipt.'
}
$suites[0].SetAttribute('name', 'php.selected.cgi')
$names = @()
foreach ($node in $nodes) {
    $stem = ($node.GetAttribute('name') -split ' \(', 2)[0]
    $relative = 'ext/session/tests/' + [IO.Path]::GetFileName($stem)
    if ($relative -notin $expected -or $node.SelectNodes('failure|error|skipped|warning').Count -ne 0) {
        throw 'Actual JUnit includes an unexpected case or result.'
    }
    $names += $relative
    $node.SetAttribute('name', $relative)
}
if (@($names | Select-Object -Unique).Count -ne $expected.Count) {
    throw 'Actual JUnit repeats a selected case.'
}
$sanitizedJunit = $xml.OuterXml
$report = Get-Content -LiteralPath $reportPath -Raw
if ($report -notmatch 'Selected patched checks passed' -or
    $sanitizedJunit -match '[A-Za-z]:[\\/]|/home/runner' -or
    $report -match '[A-Za-z]:[\\/]|/home/runner') {
    throw 'The report is incomplete or includes an absolute host path.'
}

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$phpArchive = Join-Path $repo 'lab\php-patched-validation\php-8.5.12-nts-Win32-vs17-x64.zip'
$pythonArchive = Join-Path $repo 'lab\windows\.runtime\python-3.13.17-embed-amd64.zip'
$phpArchiveSha = (Get-FileHash -LiteralPath $phpArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$pythonArchiveSha = (Get-FileHash -LiteralPath $pythonArchive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($phpArchiveSha -ne '2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477' -or
    $pythonArchiveSha -ne '9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38') {
    throw 'Pinned archive hashes changed after the guided run.'
}

$event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
$headSha = if ($event.pull_request) { $event.pull_request.head.sha } else { $env:GITHUB_SHA }
$summary = [ordered]@{
    schema = 'rpk.php.windows-hosted-bootstrap.v1'
    scope = 'Patched PHP CGI checks on a GitHub-hosted Windows 2022 image'
    repository = $env:GITHUB_REPOSITORY
    workflowRunId = $env:GITHUB_RUN_ID
    workflowAttempt = $env:GITHUB_RUN_ATTEMPT
    jobName = $env:GITHUB_JOB
    githubSha = $env:GITHUB_SHA
    headSha = $headSha
    imageOS = $env:ImageOS
    imageVersion = $env:ImageVersion
    event = $receipt.runId
    runtimeVersion = $receipt.runtimeVersion
    selectedIdentityMatch = $receipt.selectedIdentityMatch
    selectedTestsPassed = $receipt.selectedTestsPassed
    selectedCases = @($cases | ForEach-Object {
        [ordered]@{ path = $_.relativePath; failures = $_.failures; errors = $_.errors; skips = $_.skips; warnings = $_.warnings }
    })
    exitCode = $receipt.exitCode
    deadlineExceeded = $receipt.deadlineExceeded
    activeProcessesAfterCleanup = $receipt.activeProcessesAfterCleanup
    jobLimitsReadbackVerified = $receipt.jobLimitsReadbackVerified
    peakJobCommittedBytes = $receipt.peakJobCommittedBytes
    elapsedSeconds = $receipt.elapsedSeconds
    phpArchiveSha256 = $phpArchiveSha
    pythonArchiveSha256 = $pythonArchiveSha
    phpExeSha256 = $receipt.runtimeFileHashes.'php.exe'
    phpCgiExeSha256 = $receipt.runtimeFileHashes.'php-cgi.exe'
    harnessSha256 = $receipt.harnessSha256
    sourceHashes = $receipt.sourceHashes
    rawReceiptSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    rawJunitSha256 = (Get-FileHash -LiteralPath $junitPath -Algorithm SHA256).Hash.ToLowerInvariant()
    limits = 'Hosted runner and Windows Job bounds; no OS network or filesystem sandbox on this path'
}

New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'junit.xml'), $sanitizedJunit, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'report.html'), $report, [Text.UTF8Encoding]::new($false))
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'bootstrap-summary.json') -Encoding utf8
$files = @('bootstrap-summary.json', 'junit.xml', 'report.html')
$manifest = [ordered]@{
    schema = 'rpk.php.windows-hosted-bootstrap-files.v1'
    files = @($files | ForEach-Object {
        $path = Join-Path $OutputDirectory $_
        [ordered]@{
            name = $_
            bytes = (Get-Item -LiteralPath $path).Length
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
Write-Host "Saved bounded hosted bootstrap packet for $($receipt.runId)."
