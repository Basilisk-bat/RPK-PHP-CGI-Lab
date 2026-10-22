# Inert launcher contract checks. Extract named functions without running the launcher.
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'Start-Lab.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'The launcher does not parse.' }
foreach ($name in @('Assert-ExtractedFiles', 'Expand-VerifiedArchive', 'Remove-StagingDirectory', 'Html', 'Write-Report')) {
    $found = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object Name -eq $name)
    if ($found.Count -ne 1) { throw "Missing or duplicate launcher function: $name" }
    . ([scriptblock]::Create($found[0].Extent.Text))
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('rpk-launcher-check-' + [guid]::NewGuid().ToString('N'))
$full = [IO.Path]::GetFullPath($root)
$tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $full.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $full -notmatch 'rpk-launcher-check-[0-9a-f]{32}$') { throw 'Unsafe test directory.' }
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $script:LabRoot = $root
    $script:Cache = Join-Path $root 'cache'
    $script:PhpRoot = Join-Path $root 'php'
    New-Item -ItemType Directory -Path $script:Cache | Out-Null
    $NoOpen = $true
    $payload = Join-Path $root 'payload'
    New-Item -ItemType Directory -Path $payload | Out-Null
    [IO.File]::WriteAllText((Join-Path $payload 'python.exe'), 'inert expected bytes')
    $archive = Join-Path $root 'synthetic.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($payload, $archive)
    $runtime = Join-Path $script:Cache 'runtime'
    Expand-VerifiedArchive $archive $runtime @('python.exe')
    [IO.File]::WriteAllText((Join-Path $runtime 'python.exe'), 'changed inert bytes')
    $changedRejected = $false
    try { Expand-VerifiedArchive $archive $runtime @('python.exe') }
    catch { $changedRejected = $true }
    if (-not $changedRejected) { throw 'Changed cached executable was accepted.' }
    [IO.File]::WriteAllText((Join-Path $runtime 'python.exe'), 'inert expected bytes')
    [IO.File]::WriteAllText((Join-Path $runtime 'extra.dll'), 'inert extra bytes')
    $extraRejected = $false
    try { Expand-VerifiedArchive $archive $runtime @('python.exe') }
    catch { $extraRejected = $true }
    if (-not $extraRejected) { throw 'Extra cached file was accepted.' }

    foreach ($variant in @('reference-complete', 'reference-timeout', 'reference-warnings', 'reference-wrong-exit')) {
        $run = Join-Path (Join-Path $root 'runs') $variant
        New-Item -ItemType Directory -Path $run -Force | Out-Null
        $recordedExit = if ($variant -eq 'reference-timeout') { 124 } elseif ($variant -eq 'reference-wrong-exit') { 126 } else { 1 }
        $receipt = @{
            runId=$variant; runtimeVersion='8.5.11'; activeProcessesAfterCleanup=0
            harnessError=$null; junitParseError=$null; selectedIdentityMatch=$true
            deadlineExceeded=($variant -eq 'reference-timeout'); exitCode=$recordedExit
            testCases=@(
                @{failures=1;errors=0;skips=0;warnings=$(if ($variant -eq 'reference-warnings') {1} else {0})},
                @{failures=1;errors=0;skips=0;warnings=0},
                @{failures=1;errors=0;skips=0;warnings=0}
            )
        }
        $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $run 'receipt.json') -Encoding utf8
        $accepted = Write-Report $variant '8.5.11' 1
        if ($accepted -ne ($variant -eq 'reference-complete')) {
            throw "Wrong report acceptance for $variant"
        }
    }
    Write-Output 'launcher cache and report contract checks passed'
}
finally {
    # Delete only the exact fresh, checked test directory created under the OS temp root.
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}
