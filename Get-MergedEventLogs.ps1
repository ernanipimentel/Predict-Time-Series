<#
.SYNOPSIS
    Reads Application, Security, and System event logs, filters out
    Informational messages, and displays them in chronological order.

.DESCRIPTION
    Collects the most recent events from the Application, Security, and
    System Windows Event Logs, excludes entries with level "Information"
    (and "LogAlways"), merges them into a single collection, and sorts
    the result by TimeCreated ascending.

    Requires elevated privileges (Run as Administrator) to read the
    Security log.

.PARAMETER MaxEvents
    Maximum number of events to retrieve per log. Default is 200.

.PARAMETER After
    Only include events created after this date/time.
    Default is 24 hours ago.

.PARAMETER Before
    Only include events created before this date/time.
    Default is now.

.PARAMETER ExportCsv
    Optional file path. When provided the results are also exported to
    a CSV file at the given path.

.EXAMPLE
    .\Get-MergedEventLogs.ps1

    Retrieves the last 200 non-informational events per log from the
    past 24 hours.

.EXAMPLE
    .\Get-MergedEventLogs.ps1 -MaxEvents 500 -After "2026-02-10" -ExportCsv "C:\Logs\merged.csv"

    Retrieves up to 500 events per log since Feb 10 2026 and saves the
    output to a CSV file.
#>

[CmdletBinding()]
param(
    [int]$MaxEvents = 200,

    [datetime]$After = (Get-Date).AddHours(-24),

    [datetime]$Before = (Get-Date),

    [string]$ExportCsv
)

# ── Privilege check ──────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning ("Running without administrator privileges. " +
                   "The Security log may not be accessible.")
}

# ── Define the logs to query ─────────────────────────────────────────
$logNames = @('Application', 'Security', 'System')

# Levels to KEEP  (exclude Information = 4 and LogAlways = 0):
#   Critical = 1, Error = 2, Warning = 3
$levelsToKeep = @(1, 2, 3)

# ── Collect events ───────────────────────────────────────────────────
$allEvents = [System.Collections.Generic.List[object]]::new()

foreach ($logName in $logNames) {
    Write-Verbose "Querying $logName log..."

    # Build an XPath filter for the date range and severity levels.
    # Using XPath at the provider level is significantly faster than
    # filtering with Where-Object after retrieval.
    $levelConditions = ($levelsToKeep | ForEach-Object {
        "Level=$_"
    }) -join ' or '

    $afterTicks = $After.ToUniversalTime().Ticks
    $beforeTicks = $Before.ToUniversalTime().Ticks

    # TimeCreated uses FILETIME (100-ns intervals since 1601-01-01).
    # Convert .NET ticks (same epoch) directly.
    $xpath = "*[System[($levelConditions) and " +
             "TimeCreated[timediff(@SystemTime) <= " +
             "$(([datetime]::UtcNow.Ticks - $afterTicks) / 10000)] and " +
             "TimeCreated[timediff(@SystemTime) >= " +
             "$(([datetime]::UtcNow.Ticks - $beforeTicks) / 10000)]]]"

    try {
        $events = Get-WinEvent -LogName $logName `
                               -FilterXPath $xpath `
                               -MaxEvents $MaxEvents `
                               -ErrorAction Stop

        foreach ($evt in $events) {
            $allEvents.Add($evt)
        }

        Write-Verbose "  -> Retrieved $($events.Count) events from $logName."
    }
    catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "  -> No matching events in $logName."
        }
        else {
            Write-Warning "Could not read $logName log: $($_.Exception.Message)"
        }
    }
}

if ($allEvents.Count -eq 0) {
    Write-Host "No non-informational events found in the specified time range."
    return
}

# ── Sort chronologically and format ──────────────────────────────────
$sorted = $allEvents | Sort-Object -Property TimeCreated

$formatted = $sorted | Select-Object `
    @{Name = 'Time';    Expression = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }},
    @{Name = 'Level';   Expression = { $_.LevelDisplayName }},
    @{Name = 'Log';     Expression = { $_.LogName }},
    @{Name = 'Source';  Expression = { $_.ProviderName }},
    @{Name = 'EventID'; Expression = { $_.Id }},
    @{Name = 'Message'; Expression = {
        # Trim the message to the first line for table readability.
        ($_.Message -split "`n")[0].Trim()
    }}

# ── Output ───────────────────────────────────────────────────────────
$formatted | Format-Table -AutoSize -Wrap

Write-Host "`nTotal events: $($sorted.Count)" -ForegroundColor Cyan
Write-Host ("Time range : {0} - {1}" -f `
    $After.ToString('yyyy-MM-dd HH:mm:ss'), `
    $Before.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan

# ── Optional CSV export ──────────────────────────────────────────────
if ($ExportCsv) {
    # For the CSV include the full message, not the truncated one.
    $csvData = $sorted | Select-Object `
        @{Name = 'Time';    Expression = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }},
        @{Name = 'Level';   Expression = { $_.LevelDisplayName }},
        @{Name = 'Log';     Expression = { $_.LogName }},
        @{Name = 'Source';  Expression = { $_.ProviderName }},
        @{Name = 'EventID'; Expression = { $_.Id }},
        @{Name = 'Message'; Expression = { $_.Message }}

    $csvData | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to $ExportCsv" -ForegroundColor Green
}
