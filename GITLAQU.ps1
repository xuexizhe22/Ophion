param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$TargetBranch = "feature/ept-stealth-hook-poc-10507270864812334969"
$TargetRemote = "origin"

function Write-Info([string]$Message) {
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

Write-Info "Pull mode: remote branch -> git working tree."
Write-Info "Repo root: $RepoRoot"
Write-Info "Branch:    $TargetBranch"

& git -C $RepoRoot rev-parse --is-inside-work-tree | Out-Null

$CurrentBranch = (& git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
if ($CurrentBranch -ne $TargetBranch) {
    if ($DryRun) {
        Write-Info "DryRun would switch branch: $TargetBranch"
    }
    else {
        Write-Info "Switching branch to $TargetBranch"
        & git -C $RepoRoot checkout $TargetBranch | Out-Host
    }
}

$TrackedStatus = (& git -C $RepoRoot status --short --untracked-files=no)
if ($TrackedStatus) {
    Write-Warn "Working tree has tracked local changes:"
    $TrackedStatus | Out-Host
    if (-not $DryRun) {
        throw "Refusing to pull with tracked local changes present. Commit, stash, or clean the repo first."
    }
}

$UntrackedStatus = (& git -C $RepoRoot ls-files --others --exclude-standard)
if ($UntrackedStatus) {
    Write-Warn "Untracked files will be kept as-is:"
    $UntrackedStatus | Out-Host
}

if ($DryRun) {
    Write-Info "DryRun would run: git fetch $TargetRemote $TargetBranch"
    Write-Info "DryRun would run: git pull --ff-only $TargetRemote $TargetBranch"
    Write-Ok "DryRun complete. No files were changed."
    exit 0
}

Write-Info "Fetching latest branch state..."
& git -C $RepoRoot fetch $TargetRemote $TargetBranch | Out-Host

Write-Info "Pulling latest branch state..."
& git -C $RepoRoot pull --ff-only $TargetRemote $TargetBranch | Out-Host

Write-Ok "Pull complete."
