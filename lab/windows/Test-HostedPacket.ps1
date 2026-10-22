[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$ScratchRoot
)

$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'Write-HostedPacket.ps1'
$source = (Resolve-Path -LiteralPath $RunDirectory).Path
$runLeaf = Split-Path -Leaf $source
$scratch = Join-Path $ScratchRoot ('rpk-packet-probes-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null

function New-Fixture([string]$Label) {
    $directory = Join-Path (Join-Path $scratch $Label) $runLeaf
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    foreach ($name in @('receipt.json', 'junit.xml', 'report.html')) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $directory $name)
    }
    return $directory
}

function Save-Receipt([string]$Directory, $Receipt) {
    $Receipt | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath (Join-Path $Directory 'receipt.json') -Encoding utf8
}

function Assert-Rejected([string]$Label, [string]$Directory) {
    $output = Join-Path $scratch ($Label + '-packet')
    $accepted = $false
    try {
        & $exporter -RunDirectory $Directory -OutputDirectory $output | Out-Null
        $accepted = $true
    }
    catch {
        # This mutation is supposed to stop before any public packet is written.
    }
    if ($accepted -or (Test-Path -LiteralPath $output)) {
        throw "Hosted packet mutation was accepted or left output: $Label"
    }
}

$changedHash = New-Fixture 'changed-source-hash'
$receipt = Get-Content -LiteralPath (Join-Path $changedHash 'receipt.json') -Raw | ConvertFrom-Json
$receipt.sourceHashes.'run-tests.php' = '0' * 64
Save-Receipt $changedHash $receipt
Assert-Rejected 'changed-source-hash' $changedHash

$extraHash = New-Fixture 'extra-source-field'
$receipt = Get-Content -LiteralPath (Join-Path $extraHash 'receipt.json') -Raw | ConvertFrom-Json
$receipt.sourceHashes | Add-Member -NotePropertyName 'C:\PRIVATE_SENTINEL\do-not-publish.txt' -NotePropertyValue 'RPK_PRIVACY_CANARY'
Save-Receipt $extraHash $receipt
Assert-Rejected 'extra-source-field' $extraHash

$extraReceipt = New-Fixture 'extra-receipt-field'
$receipt = Get-Content -LiteralPath (Join-Path $extraReceipt 'receipt.json') -Raw | ConvertFrom-Json
$receipt | Add-Member -NotePropertyName 'privateData' -NotePropertyValue 'RPK_PRIVACY_CANARY'
Save-Receipt $extraReceipt $receipt
Assert-Rejected 'extra-receipt-field' $extraReceipt

$badLimit = New-Fixture 'wrong-job-limit'
$receipt = Get-Content -LiteralPath (Join-Path $badLimit 'receipt.json') -Raw | ConvertFrom-Json
$receipt.jobCommittedMemoryLimitBytes = 0
Save-Receipt $badLimit $receipt
Assert-Rejected 'wrong-job-limit' $badLimit

$junitExtra = New-Fixture 'junit-extra-element'
$junitPath = Join-Path $junitExtra 'junit.xml'
$junit = Get-Content -LiteralPath $junitPath -Raw
$mutatedJunit = $junit.Replace('</testsuite>', '<system-out>RPK_PRIVACY_CANARY</system-out></testsuite>')
if ($mutatedJunit -eq $junit) { throw 'The JUnit fixture could not be mutated.' }
Set-Content -LiteralPath $junitPath -Value $mutatedJunit -Encoding utf8
Assert-Rejected 'junit-extra-element' $junitExtra

$htmlExtra = New-Fixture 'html-private-comment'
Add-Content -LiteralPath (Join-Path $htmlExtra 'report.html') -Value '<!-- RPK_PRIVACY_CANARY -->'
$htmlOutput = Join-Path $scratch 'html-private-comment-packet'
& $exporter -RunDirectory $htmlExtra -OutputDirectory $htmlOutput | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $htmlOutput 'manifest.json') -PathType Leaf) -or
    @(Get-ChildItem -LiteralPath $htmlOutput -File |
        Select-String -SimpleMatch 'RPK_PRIVACY_CANARY').Count -ne 0) {
    throw 'The normalized hosted packet omitted files or copied private source text.'
}
Write-Host 'Hosted packet mutation and privacy checks passed.'
