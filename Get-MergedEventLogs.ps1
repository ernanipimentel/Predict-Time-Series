#Requires -Version 5.1

<#
.SYNOPSIS
    Reads Application, Security and System event logs, filters out
    Informational messages, and displays them in chronological order.

.DESCRIPTION
    Collects recent events from the Application, Security, and System
    Windows Event Logs.  Only Critical, Error and Warning entries are
    kept (Information and LogAlways are excluded).  The events are
    merged into a single collection and sorted by TimeCreated ascending.

    Requires elevated privileges (Run as Administrator) to read the
    Security log.

    This is a self-contained script — no external files are required.

.PARAMETER MaxEvents
    Maximum number of events to retrieve **per log**.  Default is 200.
    Must be between 1 and 100 000.

.PARAMETER After
    Only include events created after this date/time.
    Default is 24 hours before the current time.

.PARAMETER Before
    Only include events created before this date/time.
    Default is the current time.

.PARAMETER LogName
    One or more event-log names to query.
    Default is @('Application', 'Security', 'System').

.PARAMETER ExportCsv
    Optional file path.  When provided the full results are exported
    to a CSV file at the given path.

.PARAMETER ExportJson
    Optional file path.  When provided the full results are exported
    to a JSON file at the given path.

.PARAMETER PassThru
    When set the script emits structured [PSCustomObject] records to
    the pipeline instead of rendering a Format-Table.  Useful for
    piping into other commands.

.EXAMPLE
    .\Get-MergedEventLogs.ps1

    Retrieves the last 200 non-informational events per log from the
    past 24 hours and displays them as a table.

.EXAMPLE
    .\Get-MergedEventLogs.ps1 -MaxEvents 500 -After "2026-02-10" -ExportCsv C:\Logs\merged.csv

    Retrieves up to 500 events per log since 10 Feb 2026 and saves the
    output to a CSV file.

.EXAMPLE
    .\Get-MergedEventLogs.ps1 -PassThru | Where-Object Level -eq 'Error'

    Returns only Error-level events as objects for further processing.

.EXAMPLE
    .\Get-MergedEventLogs.ps1 -LogName System -ExportJson C:\Logs\system.json

    Queries only the System log and exports results as JSON.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 200,

    [datetime]$After = (Get-Date).AddHours(-24),

    [datetime]$Before = (Get-Date),

    [ValidateNotNullOrEmpty()]
    [string[]]$LogName = @('Application', 'Security', 'System'),

    [string]$ExportCsv,

    [string]$ExportJson,

    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ═════════════════════════════════════════════════════════════════════
# Helper functions (inlined — no external file required)
# ═════════════════════════════════════════════════════════════════════

function Assert-DateRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$After,
        [Parameter(Mandatory)][datetime]$Before
    )
    if ($After -ge $Before) {
        throw [System.ArgumentException]::new(
            "The -After date ($($After.ToString('o'))) must be earlier " +
            "than the -Before date ($($Before.ToString('o'))).")
    }
}

function Assert-ExportPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent -PathType Container)) {
        throw [System.IO.DirectoryNotFoundException]::new(
            "Export directory does not exist: $parent")
    }
}

function Test-AdminPrivilege {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-LevelName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][int]$LevelValue
    )
    switch ($LevelValue) {
        0 { return 'LogAlways' }
        1 { return 'Critical' }
        2 { return 'Error' }
        3 { return 'Warning' }
        4 { return 'Information' }
        5 { return 'Verbose' }
        default { return "Level-$LevelValue" }
    }
}

function Build-EventXPathFilter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][datetime]$After,
        [Parameter(Mandatory)][datetime]$Before,
        [int[]]$Levels = @(1, 2, 3)
    )

    $levelConditions = ($Levels | ForEach-Object { "Level=$_" }) -join ' or '

    $nowTicks    = [datetime]::UtcNow.Ticks
    $afterTicks  = $After.ToUniversalTime().Ticks
    $beforeTicks = $Before.ToUniversalTime().Ticks

    $afterMs  = [math]::Floor(($nowTicks - $afterTicks)  / 10000)
    $beforeMs = [math]::Floor(($nowTicks - $beforeTicks) / 10000)

    $xpath = "*[System[($levelConditions) and " +
             "TimeCreated[timediff(@SystemTime) <= $afterMs] and " +
             "TimeCreated[timediff(@SystemTime) >= $beforeMs]]]"

    return $xpath
}

function Get-FilteredEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][datetime]$After,
        [Parameter(Mandatory)][datetime]$Before,
        [int]$MaxEvents = 200
    )

    $xpath = Build-EventXPathFilter -After $After -Before $Before

    $events = Get-WinEvent -LogName $LogName `
                           -FilterXPath $xpath `
                           -MaxEvents $MaxEvents `
                           -ErrorAction Stop

    return @($events)
}

function ConvertTo-EventRecord {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )
    begin { $output = [System.Collections.Generic.List[PSCustomObject]]::new() }
    process {
        foreach ($evt in $Events) {
            $output.Add([PSCustomObject]@{
                Time    = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Level   = if ($evt.LevelDisplayName) { $evt.LevelDisplayName }
                         else { Get-LevelName -LevelValue $evt.Level }
                Log     = $evt.LogName
                Source  = $evt.ProviderName
                EventID = $evt.Id
                Message = $evt.Message
            })
        }
    }
    end { return $output.ToArray() }
}

# ═════════════════════════════════════════════════════════════════════
# Main script
# ═════════════════════════════════════════════════════════════════════

# ── Validate parameters ─────────────────────────────────────────────
Assert-DateRange -After $After -Before $Before

if ($ExportCsv)  { Assert-ExportPath -Path $ExportCsv }
if ($ExportJson) { Assert-ExportPath -Path $ExportJson }

# ── Privilege check ──────────────────────────────────────────────────
if (-not (Test-AdminPrivilege)) {
    Write-Warning ("Running without administrator privileges. " +
                   "The Security log may not be accessible.")
}

# ── Collect events ───────────────────────────────────────────────────
$allEvents = [System.Collections.Generic.List[PSObject]]::new()

foreach ($log in $LogName) {
    Write-Verbose "Querying $log log..."

    $params = @{
        LogName   = $log
        After     = $After
        Before    = $Before
        MaxEvents = $MaxEvents
    }

    try {
        $events = Get-FilteredEvents @params

        foreach ($evt in $events) {
            $allEvents.Add($evt)
        }

        Write-Verbose "  -> Retrieved $($events.Count) events from $log."
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "  -> No matching events in $log."
        }
        else {
            Write-Warning "Could not read ${log} log: $($_.Exception.Message)"
        }
    }
}

if ($allEvents.Count -eq 0) {
    Write-Host "No non-informational events found in the specified time range."
    exit 0
}

# ── Sort chronologically ────────────────────────────────────────────
$sorted = $allEvents | Sort-Object -Property TimeCreated

# ── Build output records ─────────────────────────────────────────────
$records = ConvertTo-EventRecord -Events $sorted

# ── Output ───────────────────────────────────────────────────────────
if ($PassThru) {
    $records
}
else {
    $tableRecords = $records | Select-Object Time, Level, Log, Source, EventID,
        @{Name = 'Message'; Expression = { ($_.Message -split "`n")[0].Trim() }}

    $tableRecords | Format-Table -AutoSize -Wrap

    Write-Host "`nTotal events: $($sorted.Count)" -ForegroundColor Cyan
    Write-Host ("Time range : {0} - {1}" -f `
        $After.ToString('yyyy-MM-dd HH:mm:ss'),
        $Before.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
}

# ── Optional CSV export ──────────────────────────────────────────────
if ($ExportCsv) {
    $records | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to $ExportCsv" -ForegroundColor Green
}

# ── Optional JSON export ─────────────────────────────────────────────
if ($ExportJson) {
    $records | ConvertTo-Json -Depth 3 |
        Set-Content -Path $ExportJson -Encoding UTF8
    Write-Host "Results exported to $ExportJson" -ForegroundColor Green
}
