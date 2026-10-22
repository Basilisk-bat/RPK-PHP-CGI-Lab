[CmdletBinding()]
param(
    [ValidateSet('prompt', 'patched', 'compare')][string]$Mode = 'prompt',
    [switch]$AcceptDownloads,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$script:LabRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:RepoRoot = (Resolve-Path (Join-Path $script:LabRoot '..\..')).Path
$script:Cache = Join-Path $script:LabRoot '.runtime'
$script:PhpRoot = Join-Path $script:RepoRoot 'lab\php-patched-validation'
$script:PythonVersion = '3.13.17'
$script:PythonArchive = 'python-3.13.17-embed-amd64.zip'
$script:PythonSha256 = '9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38'
$script:PhpArchives = @{
    '8.5.12' = @{
        Name = 'php-8.5.12-nts-Win32-vs17-x64.zip'
        Sha256 = '2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477'
        Folder = 'runtime'
    }
    '8.5.11' = @{
        Name = 'php-8.5.11-nts-Win32-vs17-x64.zip'
        Sha256 = '0ea96e0d2b9b737a6036f05cf4e95c49313faa6d0f27bd97edb2742503f0c043'
        Folder = 'runtime-reference-8.5.11'
    }
}

function Assert-HostReady {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'This launcher needs 64-bit Windows. See lab/windows/README.md for supported systems.'
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This launcher needs Windows. The manual cloud lab supports Linux through GitHub Actions.'
    }
    $freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
    if ($freeMemory -lt 1073741824) {
        throw 'Less than 1 GiB of RAM is available. Close your own unused applications and try again; no test was started.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($script:RepoRoot))
    if ($drive.AvailableFreeSpace -lt 1073741824) {
        throw 'Less than 1 GiB of free disk space is available. Free space on this drive and try again.'
    }
}

function Assert-Hash([string]$Path, [string]$Expected) {
    if ((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The expected archive path is not a file: $Path. Leave it in place for inspection."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "A cached download failed its official SHA-256 check: $Path. Leave it in place for inspection; this file was not used."
    }
    return $true
}

function Get-VerifiedArchive([string]$Url, [string]$Path, [string]$Expected) {
    if (Assert-Hash $Path $Expected) { return }
    if (-not $AcceptDownloads) {
        Write-Host "Official download needed: $Url"
        $reply = Read-Host 'Download and verify it now? Type Y to continue'
        if ($reply -ne 'Y') { throw 'Download declined. No test using that download was started.' }
    }
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $temporary = "$Path.download-$([guid]::NewGuid().ToString('N'))"
    try {
        Write-Host "Downloading $([IO.Path]::GetFileName($Path)) from its official site..."
        Invoke-WebRequest -Uri $Url -OutFile $temporary -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 300
        if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) { throw 'The download did not produce a file.' }
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
            throw 'The new download failed its official SHA-256 check. Its temporary file will be discarded; no code from it was run.'
        }
        Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Remove-StagingDirectory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefixes = @($script:Cache, $script:PhpRoot) | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    }
    $inside = @($prefixes | Where-Object { $full.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    if (-not $inside -or $full -notmatch '\.stage-[0-9a-f]{32}$') {
        throw 'Refusing to remove a staging directory outside the lab cache.'
    }
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}

function Assert-ExtractedFiles([string]$ArchivePath, [string]$Destination) {
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $size = [long]0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $parts = $name.TrimEnd('/').Split('/')
            if (-not $name -or $name.Contains('\') -or $name.Contains(':') -or
                $name.StartsWith('/') -or $parts -contains '..' -or $parts -contains '.' -or
                $parts -contains '') {
                throw "The verified archive has an unsafe member name: $name"
            }
            if (-not $expected.Add($name.TrimEnd('/'))) { throw "Duplicate archive member: $name" }
            if ($name.EndsWith('/')) { continue }
            $size += $entry.Length
            if ($size -gt 268435456) { throw 'The archive expands beyond the reviewed 256 MiB limit.' }
            $path = Join-Path $Destination $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "The extracted runtime is missing $name. No test using that runtime was started."
            }
            $sha = [Security.Cryptography.SHA256]::Create()
            $input = $entry.Open()
            try { $fromArchive = [BitConverter]::ToString($sha.ComputeHash($input)).Replace('-', '').ToLowerInvariant() }
            finally { $input.Dispose(); $sha.Dispose() }
            $onDisk = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($onDisk -ne $fromArchive) { throw "Extracted runtime file changed: $name. No test using that runtime was started." }
        }
        $actual = @(Get-ChildItem -LiteralPath $Destination -Recurse -Force | Where-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The extracted runtime contains a filesystem link. No test using that runtime was started.'
            }
            -not $_.PSIsContainer
        } | ForEach-Object { $_.FullName.Substring($Destination.Length).TrimStart('\', '/').Replace('\', '/') })
        $files = @($zip.Entries | Where-Object { -not $_.FullName.EndsWith('/') } | ForEach-Object { $_.FullName })
        if ($actual.Count -ne $files.Count -or @($actual | Where-Object { -not $expected.Contains($_) }).Count -gt 0) {
            throw 'The extracted runtime contains missing or extra files. No test using that runtime was started.'
        }
    }
    finally { $zip.Dispose() }
}

function Expand-VerifiedArchive([string]$ArchivePath, [string]$Destination, [string[]]$RequiredFiles) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) {
        foreach ($required in $RequiredFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $Destination $required) -PathType Leaf)) {
                throw "The existing runtime folder is incomplete: $Destination. Leave it in place for inspection; no test using it was started."
            }
        }
        Assert-ExtractedFiles $ArchivePath $Destination
        return
    }
    $stage = "$Destination.stage-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        # Validate member names and total size before extraction, using the empty staging directory.
        # Missing-file rejection is deferred until extraction has completed.
        $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try {
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $size = [long]0
            foreach ($entry in $zip.Entries) {
                $name = $entry.FullName
                $parts = $name.TrimEnd('/').Split('/')
                if (-not $name -or $name.Contains('\') -or $name.Contains(':') -or
                    $name.StartsWith('/') -or $parts -contains '..' -or $parts -contains '.' -or
                    $parts -contains '') { throw "Unsafe archive member name: $name" }
                if (-not $seen.Add($name.TrimEnd('/'))) { throw "Duplicate archive member: $name" }
                $size += $entry.Length
                if ($size -gt 268435456) { throw 'The archive expands beyond the reviewed 256 MiB limit.' }
            }
        }
        finally { $zip.Dispose() }
        [IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $stage)
        foreach ($required in $RequiredFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) {
                throw "Archive extraction did not produce $required."
            }
        }
        Assert-ExtractedFiles $ArchivePath $stage
        Move-Item -LiteralPath $stage -Destination $Destination -ErrorAction Stop
    }
    finally {
        Remove-StagingDirectory $stage
    }
}

function Html([string]$Value) { return [Net.WebUtility]::HtmlEncode($Value) }

function Write-Report([string]$RunId, [string]$Version, [int]$RunnerExit) {
    $run = Join-Path (Join-Path $script:LabRoot 'runs') $RunId
    if (-not (Test-Path -LiteralPath $run -PathType Container)) {
        throw 'The runner stopped before creating a run folder. Check the error above; no result was accepted.'
    }
    $receiptPath = Join-Path $run 'receipt.json'
    $status = 'No result was verified'
    $detail = 'The test did not produce a complete accepted receipt. Keep the run folder for review.'
    $good = $false
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($receipt.runId -eq $RunId -and $receipt.runtimeVersion -eq $Version -and
            $receipt.activeProcessesAfterCleanup -eq 0 -and -not $receipt.harnessError -and
            -not $receipt.junitParseError -and $receipt.deadlineExceeded -eq $false) {
            if ($Version -eq '8.5.12' -and $RunnerExit -eq 0 -and $receipt.selectedTestsPassed) {
                $status = 'Selected patched checks passed'
                $detail = 'All three selected fresh-process CGI tests passed in PHP 8.5.12.'
                $good = $true
            }
            elseif ($Version -eq '8.5.11' -and $RunnerExit -eq 1 -and
                $receipt.exitCode -eq 1 -and $receipt.selectedIdentityMatch -and
                $receipt.testCases.Count -eq 3 -and
                @($receipt.testCases | Where-Object { $_.failures -gt 0 -and $_.errors -eq 0 -and
                    $_.skips -eq 0 -and $_.warnings -eq 0 }).Count -eq 3) {
                $status = 'Older reference showed the selected difference'
                $detail = 'The three selected cases failed in PHP 8.5.11. This is comparison evidence, not a successful defensive result.'
                $good = $true
            }
        }
    }
    $title = Html $status
    $body = Html $detail
    $versionText = Html $Version
    $runText = Html $RunId
    $html = @"
<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RPK PHP CGI Lab result</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#08090b;color:#f3eae8;font:16px/1.55 Consolas,'Cascadia Mono',monospace}
main{max-width:58rem;margin:auto;padding:clamp(1.5rem,6vw,5rem)}.kicker{color:#ff715f;letter-spacing:.13em;text-transform:uppercase}
h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.12;font-weight:600}p{max-width:70ch}section{border-top:1px solid #8b4b46;padding-top:1.4rem;margin-top:2rem}
a{color:#ff998c}a:focus-visible{outline:3px solid #ff715f;outline-offset:3px}.signal{border:1px solid #ff715f;padding:1.2rem;background:#180e0e}
small{color:#cbb9b6}@media(forced-colors:active){.signal{border:1px solid CanvasText}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style>
<main><p class="kicker">RPK / local experiment</p><h1>$title</h1>
<div class="signal"><p>$body</p><p><strong>PHP:</strong> $versionText<br><strong>Run:</strong> $runText</p></div>
<section><h2>What this tells you</h2><p>These are selected PHP session-upload tests using fresh local CGI processes. This result does not prove an exploit, cover every vulnerability path, test a persistent server, or show that a website was updated.</p>
<p>Review the local <a href="receipt.json">receipt</a> and <a href="junit.xml">test details</a>. Keep those files private if they contain machine paths.</p></section>
<section><h2>Next step</h2><p>For an owned website, ask its administrator to check the PHP version actually serving requests and apply the vendor's fixed build. The lab never changes a website or system PHP installation.</p></section>
<small>Generated locally. No report was uploaded by this launcher.</small></main></html>
"@
    $path = Join-Path $run 'report.html'
    [IO.File]::WriteAllText($path, $html, [Text.UTF8Encoding]::new($false))
    Write-Host "Result: $status"
    Write-Host "Local report: $path"
    if (-not $NoOpen) { Start-Process -FilePath $path }
    return $good
}

$launcherLock = $null
try {
    New-Item -ItemType Directory -Force -Path $script:Cache | Out-Null
    $lockPath = Join-Path $script:Cache 'launcher.lock'
    try { $launcherLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch [IO.IOException] { throw 'Another launcher may be using this folder. Wait for it to finish, then retry.' }
    Assert-HostReady
    if ($Mode -eq 'prompt') {
        Write-Host 'RPK PHP CGI Regression Lab'
        Write-Host '1. Run selected patched PHP checks (recommended)'
        Write-Host '2. Compare patched PHP with an older reference release'
        $choice = Read-Host 'Type 1 or 2'
        if ($choice -eq '1') { $Mode = 'patched' }
        elseif ($choice -eq '2') { $Mode = 'compare' }
        else { throw 'No option selected. No test was started.' }
    }
    $versions = if ($Mode -eq 'compare') { @('8.5.12', '8.5.11') } else { @('8.5.12') }
    $pythonUrl = "https://www.python.org/ftp/python/$script:PythonVersion/$script:PythonArchive"
    $pythonZip = Join-Path $script:Cache $script:PythonArchive
    Get-VerifiedArchive $pythonUrl $pythonZip $script:PythonSha256
    $pythonDir = Join-Path $script:Cache 'python-3.13.17'
    Expand-VerifiedArchive $pythonZip $pythonDir @('python.exe')
    $python = Join-Path $pythonDir 'python.exe'
    $pythonBanner = (& $python --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $pythonBanner -ne "Python $script:PythonVersion") {
        throw 'The pinned portable Python did not start with its expected version. No PHP test was started.'
    }
    foreach ($version in $versions) {
        $info = $script:PhpArchives[$version]
        $archive = Join-Path $script:PhpRoot $info.Name
        $url = "https://downloads.php.net/~windows/releases/archives/$($info.Name)"
        Get-VerifiedArchive $url $archive $info.Sha256
        Expand-VerifiedArchive $archive (Join-Path $script:PhpRoot $info.Folder) @('php.exe', 'php-cgi.exe')
        $runId = ('local-' + $version.Replace('.', '-') + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)).ToLowerInvariant()
        Write-Host "Running selected checks with PHP $version. This may take a few minutes..."
        $arguments = @((Join-Path $script:LabRoot 'run-cgi-regressions.py'), $runId, '--runtime-version', $version)
        if ($version -eq '8.5.11') { $arguments += '--allow-unpatched-reference' }
        & $python @arguments | Out-Null
        $runnerExit = $LASTEXITCODE
        if (-not (Write-Report $runId $version $runnerExit)) {
            throw "The PHP $version selected result could not be accepted. Review its local report."
        }
    }
    Write-Host 'Done. The report describes the limited result and next step.'
    exit 0
}
catch {
    Write-Host "RPK Lab stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'The launcher did not change a website, installed PHP service, or system setting. Local cache or run files may have been written.'
    exit 2
}
finally {
    if ($launcherLock) { $launcherLock.Dispose() }
}
