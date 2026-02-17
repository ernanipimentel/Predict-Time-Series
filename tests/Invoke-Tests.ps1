#Requires -Version 5.1

<#
.SYNOPSIS
    Runs the Pester test suite for Get-MergedEventLogs.

.DESCRIPTION
    Installs Pester 5 (if needed) and executes all *.Tests.ps1 files
    in this directory.  Returns a non-zero exit code on failure so it
    can be used in CI pipelines.

.EXAMPLE
    pwsh -File .\tests\Invoke-Tests.ps1
#>

$ErrorActionPreference = 'Stop'

# ── Ensure Pester 5+ is available ────────────────────────────────────
$minVersion = [version]'5.0.0'
$pester = Get-Module -Name Pester -ListAvailable |
          Where-Object { $_.Version -ge $minVersion } |
          Sort-Object Version -Descending |
          Select-Object -First 1

if (-not $pester) {
    Write-Host 'Installing Pester 5...' -ForegroundColor Yellow
    Install-Module -Name Pester -MinimumVersion '5.0.0' `
                   -Force -Scope CurrentUser -SkipPublisherCheck
}

Import-Module Pester -MinimumVersion '5.0.0' -Force

# ── Run tests ────────────────────────────────────────────────────────
$config = [PesterConfiguration]::Default

$config.Run.Path           = $PSScriptRoot
$config.Run.Exit           = $true
$config.Output.Verbosity   = 'Detailed'
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath   = Join-Path $PSScriptRoot 'test-results.xml'
$config.TestResult.OutputFormat = 'NUnitXml'

Invoke-Pester -Configuration $config
