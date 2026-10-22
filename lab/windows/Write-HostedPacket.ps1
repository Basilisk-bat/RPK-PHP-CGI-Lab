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
foreach ($inputFile in @(
    @{ Path = $receiptPath; Limit = 1048576 },
    @{ Path = $junitPath; Limit = 1048576 },
    @{ Path = $reportPath; Limit = 65536 }
)) {
    $item = Get-Item -LiteralPath $inputFile.Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $inputFile.Limit -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A hosted result input is not a bounded regular file.'
    }
}
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$allowedReceiptFields = @(
    'runId', 'runtimeVersion', 'selectedTests', 'command', 'startedAtUtc',
    'localhostAddresses', 'environment', 'deadlineSeconds', 'runtimeSha256',
    'runtimeFileHashes', 'harnessSha256', 'sourceHashes', 'networkIsolation',
    'serverBinding', 'availablePhysicalMiBBeforeStart', 'jobCommittedMemoryLimitBytes',
    'jobActiveProcessLimit', 'limitScope', 'proofScope', 'jobLimitsReadbackVerified',
    'runnerProcessId', 'deadlineExceeded', 'exitCode', 'activeProcessesAfterRunner',
    'totalProcesses', 'activeProcessesAfterGrace', 'forcedDescendantCleanup',
    'activeProcessesAfterCleanup', 'peakJobCommittedBytes', 'elapsedSeconds',
    'testCases', 'selectedIdentityMatch', 'selectedTestsPassed', 'finishedAtUtc'
)
$actualReceiptFields = @($receipt.PSObject.Properties.Name)
if ($actualReceiptFields.Count -ne $allowedReceiptFields.Count -or
    @($actualReceiptFields | Where-Object { $_ -notin $allowedReceiptFields }).Count -ne 0) {
    throw 'The receipt schema changed; review its fields before public export.'
}
$expected = @(
    'ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt',
    'ext/session/tests/rfc1867_no_user_code.phpt',
    'ext/session/tests/rfc1867_sid_invalid.phpt'
)
$cases = @($receipt.testCases)
if ($receipt.runId -notmatch '^local-8-5-12-[0-9]{8}t[0-9]{6}-[0-9a-f]{8}$' -or
    $receipt.runId -ne (Split-Path -Leaf $run) -or $receipt.runtimeVersion -ne '8.5.12' -or
    $receipt.exitCode -ne 0 -or $receipt.selectedTestsPassed -ne $true -or
    $receipt.selectedIdentityMatch -ne $true -or $receipt.deadlineExceeded -ne $false -or
    $receipt.activeProcessesAfterCleanup -ne 0 -or $receipt.jobLimitsReadbackVerified -ne $true -or
    $receipt.jobCommittedMemoryLimitBytes -ne 268435456 -or
    $receipt.jobActiveProcessLimit -ne 16 -or $receipt.deadlineSeconds -ne 90 -or
    [long]$receipt.peakJobCommittedBytes -lt 0 -or
    [long]$receipt.peakJobCommittedBytes -gt 268435456 -or
    [double]$receipt.elapsedSeconds -lt 0 -or [double]$receipt.elapsedSeconds -gt 90 -or
    $receipt.harnessError -or $receipt.junitParseError -or $cases.Count -ne $expected.Count -or
    @($cases | Where-Object { $_.relativePath -notin $expected -or
        $_.failures -ne 0 -or $_.errors -ne 0 -or $_.skips -ne 0 -or $_.warnings -ne 0 }).Count -ne 0 -or
    @($cases | Select-Object -ExpandProperty relativePath -Unique).Count -ne $expected.Count) {
    throw 'Hosted receipt failed selected identity, result, bounds or cleanup checks.'
}

$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.XmlResolver = $null
$xml.Load($junitPath)
if ($xml.DocumentType) { throw 'JUnit document types are not accepted.' }
$suites = $xml.SelectNodes('/testsuites/testsuite')
$nodes = $xml.SelectNodes('/testsuites/testsuite/testcase')
if ($suites.Count -ne 1 -or $nodes.Count -ne $expected.Count -or
    $xml.DocumentElement.SelectNodes('*').Count -ne 1 -or
    $suites[0].SelectNodes('*').Count -ne $expected.Count -or
    $xml.DocumentElement.GetAttribute('tests') -ne '3' -or
    $xml.DocumentElement.GetAttribute('failures') -ne '0' -or
    $xml.DocumentElement.GetAttribute('errors') -ne '0' -or
    $xml.DocumentElement.GetAttribute('skip') -ne '0' -or
    $suites[0].GetAttribute('tests') -ne '3' -or
    $suites[0].GetAttribute('failures') -ne '0' -or
    $suites[0].GetAttribute('errors') -ne '0' -or
    $suites[0].GetAttribute('skip') -ne '0') {
    throw 'Actual JUnit shape or outcome differs from the receipt.'
}
$names = @()
foreach ($node in $nodes) {
    $stem = ($node.GetAttribute('name') -split ' \(', 2)[0]
    $relative = 'ext/session/tests/' + [IO.Path]::GetFileName($stem)
    $attributes = @($node.Attributes | ForEach-Object { $_.Name })
    if ($relative -notin $expected -or $node.SelectNodes('*').Count -ne 0 -or
        @($attributes | Where-Object { $_ -notin @('name', 'time') }).Count -ne 0 -or
        $node.GetAttribute('time') -notmatch '^[0-9]+(\.[0-9]+)?$') {
        throw 'Actual JUnit includes an unexpected case or result.'
    }
    $names += $relative
}
if (@($names | Select-Object -Unique).Count -ne $expected.Count) {
    throw 'Actual JUnit repeats a selected case.'
}
$normalized = New-Object System.Xml.XmlDocument
$null = $normalized.AppendChild($normalized.CreateXmlDeclaration('1.0', 'UTF-8', $null))
$rootElement = $normalized.CreateElement('testsuites')
$rootElement.SetAttribute('tests', '3')
$rootElement.SetAttribute('failures', '0')
$rootElement.SetAttribute('errors', '0')
$rootElement.SetAttribute('skip', '0')
$null = $normalized.AppendChild($rootElement)
$suiteElement = $normalized.CreateElement('testsuite')
$suiteElement.SetAttribute('name', 'php.selected.cgi')
$suiteElement.SetAttribute('tests', '3')
$suiteElement.SetAttribute('failures', '0')
$suiteElement.SetAttribute('errors', '0')
$suiteElement.SetAttribute('skip', '0')
$null = $rootElement.AppendChild($suiteElement)
foreach ($relative in @($names | Sort-Object)) {
    $caseElement = $normalized.CreateElement('testcase')
    $caseElement.SetAttribute('name', $relative)
    $null = $suiteElement.AppendChild($caseElement)
}
$sanitizedJunit = $normalized.OuterXml
$originalReport = Get-Content -LiteralPath $reportPath -Raw
if ($originalReport -notmatch 'Selected patched checks passed' -or
    $originalReport -match '(?i)<\s*(script|iframe|object|embed)\b|\bon[a-z]+\s*=') {
    throw 'The local HTML report is incomplete or contains active markup.'
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
$sourceManifest = Get-Content -LiteralPath (Join-Path $repo 'lab\windows\source-manifest.json') -Raw | ConvertFrom-Json
$sourcePaths = @('run-tests.php') + $expected + @('ext/session/tests/skipif.inc')
$allSourcePaths = @($sourcePaths) + @('LICENSE')
$manifestFiles = @($sourceManifest.files)
$manifestPaths = @($manifestFiles | ForEach-Object { $_.path })
if ($manifestFiles.Count -ne $allSourcePaths.Count -or
    @($manifestPaths | Where-Object { $_ -notin $allSourcePaths }).Count -ne 0 -or
    @($manifestPaths | Select-Object -Unique).Count -ne $allSourcePaths.Count) {
    throw 'The source manifest selection changed; review it before public export.'
}
$receiptSourcePaths = @($receipt.sourceHashes.PSObject.Properties.Name)
if ($receiptSourcePaths.Count -ne $sourcePaths.Count -or
    @($receiptSourcePaths | Where-Object { $_ -notin $sourcePaths }).Count -ne 0) {
    throw 'The receipt source-hash fields changed; review them before public export.'
}
$safeSourceHashes = [ordered]@{}
foreach ($entry in $manifestFiles) {
    if ($entry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'A source manifest digest is malformed.'
    }
    $sourceFile = Join-Path (Join-Path $repo 'lab\windows\source') $entry.path
    $actualSha = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha -ne $entry.sha256) { throw 'A pinned source file changed.' }
    if ($entry.path -in $sourcePaths) {
        $receiptSha = $receipt.sourceHashes.PSObject.Properties[$entry.path].Value
        if ($receiptSha -cne $actualSha) { throw 'Receipt source identity differs from pinned source bytes.' }
        $safeSourceHashes[$entry.path] = $actualSha
    }
}
$runtime = Join-Path $repo 'lab\php-patched-validation\runtime'
$phpExeSha = (Get-FileHash -LiteralPath (Join-Path $runtime 'php.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$phpCgiExeSha = (Get-FileHash -LiteralPath (Join-Path $runtime 'php-cgi.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$harnessSha = (Get-FileHash -LiteralPath (Join-Path $repo 'lab\windows\run-cgi-regressions.py') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($receipt.runtimeSha256 -cne $phpExeSha -or
    $receipt.runtimeFileHashes.'php.exe' -cne $phpExeSha -or
    $receipt.runtimeFileHashes.'php-cgi.exe' -cne $phpCgiExeSha -or
    $receipt.harnessSha256 -cne $harnessSha) {
    throw 'Receipt runtime or harness identity differs from the checked files.'
}

$event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
$headSha = if ($event.pull_request) { $event.pull_request.head.sha } else { $env:GITHUB_SHA }
if ($env:GITHUB_REPOSITORY -ne 'Basilisk-bat/RPK-PHP-CGI-Lab' -or
    $env:GITHUB_RUN_ID -notmatch '^[0-9]+$' -or
    $env:GITHUB_RUN_ATTEMPT -notmatch '^[0-9]+$' -or
    $env:GITHUB_JOB -ne 'fresh-patched-launcher' -or
    $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$' -or
    $headSha -notmatch '^[0-9a-f]{40}$' -or
    $env:ImageOS -ne 'win22' -or
    $env:ImageVersion -notmatch '^[0-9]{8}\.[0-9]+\.[0-9]+$') {
    throw 'Hosted runner identity is missing or outside the reviewed format.'
}
$safeEvent = [Net.WebUtility]::HtmlEncode($receipt.runId)
$sanitizedReport = @"
<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>RPK PHP CGI hosted bootstrap result</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#08090b;color:#f3eae8;font:16px/1.55 Consolas,'Cascadia Mono',monospace}main{max-width:58rem;margin:auto;padding:clamp(1.5rem,6vw,5rem)}.kicker{color:#ff715f;letter-spacing:.13em;text-transform:uppercase}h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.12;font-weight:600}p{max-width:70ch}section{border-top:1px solid #8b4b46;padding-top:1.4rem;margin-top:2rem}.signal{border:1px solid #ff715f;padding:1.2rem;background:#180e0e}small{color:#cbb9b6}@media(forced-colors:active){.signal{border:1px solid CanvasText}}</style>
<main><p class="kicker">RPK / hosted Windows bootstrap</p><h1>Selected patched checks passed</h1>
<div class="signal"><p>PHP 8.5.12 passed the three selected fresh-process CGI cases on the recorded GitHub hosted Windows runner.</p><p>Event: <code>$safeEvent</code></p></div>
<section><h2>Read the evidence</h2><p>The packet contains a normalized JUnit result, validated source and runtime hashes, Job bounds and runner identity in <code>bootstrap-summary.json</code>. Match its run and commit to GitHub before citing it.</p></section>
<section><h2>Limit</h2><p>This scripted check uses a preconfigured Windows runner. It does not test a missing Visual C++ prerequisite, the interactive local menu, OS network or filesystem isolation, a persistent server or a deployed PHP repair.</p></section>
<small>Generated from allowlisted values. The original local receipt, JUnit and HTML were not uploaded.</small></main></html>
"@
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
    jobCommittedMemoryLimitBytes = $receipt.jobCommittedMemoryLimitBytes
    jobActiveProcessLimit = $receipt.jobActiveProcessLimit
    deadlineSeconds = $receipt.deadlineSeconds
    peakJobCommittedBytes = $receipt.peakJobCommittedBytes
    elapsedSeconds = $receipt.elapsedSeconds
    phpArchiveSha256 = $phpArchiveSha
    pythonArchiveSha256 = $pythonArchiveSha
    phpExeSha256 = $phpExeSha
    phpCgiExeSha256 = $phpCgiExeSha
    harnessSha256 = $harnessSha
    sourceHashes = $safeSourceHashes
    rawReceiptSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    rawJunitSha256 = (Get-FileHash -LiteralPath $junitPath -Algorithm SHA256).Hash.ToLowerInvariant()
    rawReportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    limits = 'Hosted runner and Windows Job bounds; no OS network or filesystem sandbox on this path'
}

$summaryJson = $summary | ConvertTo-Json -Depth 8
if ($summaryJson -match '[A-Za-z]:[\\/]|/home/runner' -or
    $sanitizedJunit -match '[A-Za-z]:[\\/]|/home/runner' -or
    $sanitizedReport -match '[A-Za-z]:[\\/]|/home/runner') {
    throw 'Refusing to publish an absolute host path.'
}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'junit.xml'), $sanitizedJunit, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'report.html'), $sanitizedReport, [Text.UTF8Encoding]::new($false))
$summaryJson | Set-Content -LiteralPath (Join-Path $OutputDirectory 'bootstrap-summary.json') -Encoding utf8
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
