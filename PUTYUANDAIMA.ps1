param(
    [string]$CommitMessage = "",
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

Write-Info "Upload mode: git working tree -> remote branch."
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

$StatusOutput = (& git -C $RepoRoot status --short)
if (-not $StatusOutput) {
    Write-Ok "No local changes to upload."
    exit 0
}

$StatusOutput | Out-Host

if ($DryRun) {
    Write-Ok "DryRun complete. No git add/commit/push was executed."
    exit 0
}

Write-Info "Staging changes..."
& git -C $RepoRoot add -A | Out-Host

if ([string]::IsNullOrWhiteSpace($CommitMessage)) {
    $CommitMessage = "Update Ophion working tree $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

Write-Info "Creating commit..."
& git -C $RepoRoot commit -m $CommitMessage | Out-Host

Write-Info "Pushing to remote branch..."
& git -C $RepoRoot push $TargetRemote $TargetBranch | Out-Host

Write-Ok "Upload complete."
