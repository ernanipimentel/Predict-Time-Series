#Requires -Version 5.1

<#
.SYNOPSIS
    Helper functions for Get-MergedEventLogs -- used by the Pester tests.

.DESCRIPTION
    Contains the same helper functions that are inlined inside
    Get-MergedEventLogs.ps1.  This standalone file exists so the
    Pester test suite can dot-source individual functions without
    executing the main script.

    The main script is fully self-contained and does NOT depend on
    this file at runtime.
#>

Set-StrictMode -Version Latest

function Show-ScriptHelp {
    <#
    .SYNOPSIS
        Prints a formatted help page to the console and returns.
        Called when the user passes -Help or -h.
    #>
    [CmdletBinding()]
    param()

    # ── Colour shortcuts (safe for 5.1; fall back if redirected) ─────
    $cyan    = 'Cyan'
    $yellow  = 'Yellow'
    $green   = 'Green'
    $white   = 'White'

    # ── Title / Objective ────────────────────────────────────────────
    Write-Host ''
    Write-Host '====================================================================' -ForegroundColor $cyan
    Write-Host '  Get-MergedEventLogs.ps1  --  Windows Event Log Consolidator'        -ForegroundColor $cyan
    Write-Host '====================================================================' -ForegroundColor $cyan
    Write-Host ''
    Write-Host 'OBJECTIVE' -ForegroundColor $yellow
    Write-Host '  Collects Critical, Error and Warning events from one or more'
    Write-Host '  Windows Event Logs, merges them into a single chronological'
    Write-Host '  timeline, and presents the result as a table, CSV, or JSON.'
    Write-Host '  Informational and LogAlways events are automatically excluded.'
    Write-Host ''

    # ── Pre-requisites ───────────────────────────────────────────────
    Write-Host 'PRE-REQUISITES' -ForegroundColor $yellow
    Write-Host '  - Windows PowerShell 5.1 or PowerShell 7+ (runs on both).'
    Write-Host '  - The Windows Event Log service must be running.'
    Write-Host '  - Administrator (elevated) privileges are required to read'
    Write-Host '    the Security log.  Other logs can be read without elevation.'
    Write-Host '  - No external modules or files are needed; the script is'
    Write-Host '    completely self-contained.'
    Write-Host ''

    # ── Parameters ───────────────────────────────────────────────────
    Write-Host 'PARAMETERS' -ForegroundColor $yellow
    Write-Host ''
    Write-Host '  -MaxEvents <int>' -ForegroundColor $green
    Write-Host '      Maximum events to retrieve PER LOG (not total).'
    Write-Host '      Range : 1 .. 100,000'
    Write-Host '      Default: 200'
    Write-Host ''
    Write-Host '  -After <datetime>' -ForegroundColor $green
    Write-Host '      Only include events created after this date/time.'
    Write-Host '      Accepts any format recognised by PowerShell, for example:'
    Write-Host '        "2026-02-10"  or  "2026-02-10 08:00:00"'
    Write-Host '      Default: 24 hours ago'
    Write-Host ''
    Write-Host '  -Before <datetime>' -ForegroundColor $green
    Write-Host '      Only include events created before this date/time.'
    Write-Host '      Must be later than -After (see CONFLICTS below).'
    Write-Host '      Default: now'
    Write-Host ''
    Write-Host '  -LogName <string[]>' -ForegroundColor $green
    Write-Host '      One or more event-log names to query.'
    Write-Host '      Default: Application, Security, System'
    Write-Host '      Example: -LogName System'
    Write-Host '               -LogName Application,System'
    Write-Host ''
    Write-Host '  -ExportCsv <string>' -ForegroundColor $green
    Write-Host '      File path for CSV export.  The parent directory must exist.'
    Write-Host '      Full (untruncated) messages are written to the CSV.'
    Write-Host ''
    Write-Host '  -ExportJson <string>' -ForegroundColor $green
    Write-Host '      File path for JSON export.  The parent directory must exist.'
    Write-Host '      Full (untruncated) messages are written to the JSON.'
    Write-Host ''
    Write-Host '  -PassThru' -ForegroundColor $green
    Write-Host '      Emits [PSCustomObject] records to the pipeline instead of'
    Write-Host '      displaying a formatted table.  Useful for piping results'
    Write-Host '      into Where-Object, Sort-Object, Export-Csv, etc.'
    Write-Host '      When -PassThru is used the summary banner is suppressed.'
    Write-Host ''
    Write-Host '  -Help | -h' -ForegroundColor $green
    Write-Host '      Displays this help page and exits.'
    Write-Host ''
    Write-Host '  -Verbose' -ForegroundColor $green
    Write-Host '      Shows detailed progress messages during execution,'
    Write-Host '      including per-log query status, XPath filters used,'
    Write-Host '      event counts, and timing information.'
    Write-Host ''

    # ── Parameter conflicts ──────────────────────────────────────────
    Write-Host 'PARAMETER CONFLICTS' -ForegroundColor $yellow
    Write-Host '  -After must be earlier than -Before.  If they are equal or'
    Write-Host '    reversed the script will terminate with an error.'
    Write-Host ''
    Write-Host '  -PassThru suppresses the console table and summary banner.'
    Write-Host '    You can still combine it with -ExportCsv or -ExportJson;'
    Write-Host '    the exports are written normally while the objects go to'
    Write-Host '    the pipeline.'
    Write-Host ''
    Write-Host '  -ExportCsv and -ExportJson can be used at the same time.'
    Write-Host '    Both files will be created from the same result set.'
    Write-Host ''
    Write-Host '  -Help ignores all other parameters.  When -Help is present'
    Write-Host '    the script shows this page and exits without querying logs.'
    Write-Host ''

    # ── Examples ─────────────────────────────────────────────────────
    Write-Host 'EXAMPLES' -ForegroundColor $yellow
    Write-Host ''
    Write-Host '  1. Basic usage (last 24 hours, all three logs):' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1' -ForegroundColor $green
    Write-Host ''
    Write-Host '  2. Last 7 days, up to 500 events per log:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -MaxEvents 500 -After (Get-Date).AddDays(-7)' -ForegroundColor $green
    Write-Host ''
    Write-Host '  3. Specific date range with CSV export:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -After "2026-02-01" -Before "2026-02-15" `' -ForegroundColor $green
    Write-Host '         -ExportCsv C:\Logs\merged.csv' -ForegroundColor $green
    Write-Host ''
    Write-Host '  4. System log only, export to JSON:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -LogName System -ExportJson C:\Logs\system.json' -ForegroundColor $green
    Write-Host ''
    Write-Host '  5. Pipeline: get only Error events:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -PassThru | Where-Object Level -eq "Error"' -ForegroundColor $green
    Write-Host ''
    Write-Host '  6. Pipeline: count events per log:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -PassThru | Group-Object Log' -ForegroundColor $green
    Write-Host ''
    Write-Host '  7. Verbose mode to see progress:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -Verbose' -ForegroundColor $green
    Write-Host ''
    Write-Host '  8. Both CSV and JSON export at once:' -ForegroundColor $white
    Write-Host '     .\Get-MergedEventLogs.ps1 -ExportCsv C:\Logs\out.csv `' -ForegroundColor $green
    Write-Host '         -ExportJson C:\Logs\out.json' -ForegroundColor $green
    Write-Host ''
    Write-Host '====================================================================' -ForegroundColor $cyan
    Write-Host ''
}

function Assert-DateRange {
    <#
    .SYNOPSIS  Validates that -After is strictly earlier than -Before.
    .DESCRIPTION
        Compares two datetime values and throws a descriptive
        ArgumentException when -After is equal to or later than -Before.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$After,

        [Parameter(Mandatory)]
        [datetime]$Before
    )

    if ($After -ge $Before) {
        throw [System.ArgumentException]::new(
            "The -After date ($($After.ToString('o'))) must be earlier " +
            "than the -Before date ($($Before.ToString('o'))).")
    }
}

function Assert-ExportPath {
    <#
    .SYNOPSIS  Validates that the parent directory of an export path exists.
    .DESCRIPTION
        Extracts the parent folder from the supplied path and checks
        that it is a valid directory.  Throws DirectoryNotFoundException
        when the directory is missing so the error is caught early,
        before the script does any expensive log queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent -PathType Container)) {
        throw [System.IO.DirectoryNotFoundException]::new(
            "Export directory does not exist: $parent")
    }
}

function Test-AdminPrivilege {
    <#
    .SYNOPSIS  Returns $true when the current session is elevated.
    .DESCRIPTION
        Uses WindowsPrincipal.IsInRole to detect Administrator status.
        Returns $false (instead of throwing) on non-Windows platforms
        so the script can still run with a warning.
    #>
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

function Build-EventXPathFilter {
    <#
    .SYNOPSIS  Builds an XPath filter string for Get-WinEvent.
    .DESCRIPTION
        Produces an XPath 1.0 expression that selects events matching
        the specified severity levels within a time window.  The time
        window is expressed as millisecond offsets from "now" using the
        timediff() function understood by the Windows Event Log engine.

        Using XPath at the provider level is significantly faster than
        retrieving all events and filtering with Where-Object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [datetime]$After,

        [Parameter(Mandatory)]
        [datetime]$Before,

        [int[]]$Levels = @(1, 2, 3)
    )

    $levelConditions = ($Levels | ForEach-Object { "Level=$_" }) -join ' or '

    $nowTicks    = [datetime]::UtcNow.Ticks
    $afterTicks  = $After.ToUniversalTime().Ticks
    $beforeTicks = $Before.ToUniversalTime().Ticks

    # timediff(@SystemTime) returns milliseconds between "now" and the
    # event timestamp.  A larger value means the event is older.
    #   - Events AFTER  $After  -> timediff <= (now - After)  ms
    #   - Events BEFORE $Before -> timediff >= (now - Before) ms
    $afterMs  = [math]::Floor(($nowTicks - $afterTicks)  / 10000)
    $beforeMs = [math]::Floor(($nowTicks - $beforeTicks) / 10000)

    $xpath = "*[System[($levelConditions) and " +
             "TimeCreated[timediff(@SystemTime) <= $afterMs] and " +
             "TimeCreated[timediff(@SystemTime) >= $beforeMs]]]"

    return $xpath
}

function Get-FilteredEvents {
    <#
    .SYNOPSIS  Retrieves non-informational events from a single log.
    .DESCRIPTION
        Builds an XPath filter via Build-EventXPathFilter and calls
        Get-WinEvent.  Returns an array of event-log record objects.
        Throws when no events match (caller decides how to handle).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [datetime]$After,

        [Parameter(Mandatory)]
        [datetime]$Before,

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
    <#
    .SYNOPSIS  Converts raw event-log objects to uniform PSCustomObjects.
    .DESCRIPTION
        Each output object has the properties: Time, Level, Log, Source,
        EventID, Message.  If the raw event lacks a LevelDisplayName
        (can happen with forwarded or third-party events) the function
        falls back to Get-LevelName using the numeric Level value.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )

    begin {
        $output = New-Object 'System.Collections.Generic.List[PSCustomObject]'
    }
    process {
        foreach ($evt in $Events) {
            # Determine the display name for the level; fall back to
            # the numeric mapping when the property is empty.
            if ($evt.LevelDisplayName) {
                $levelText = $evt.LevelDisplayName
            }
            else {
                $levelText = Get-LevelName -LevelValue $evt.Level
            }

            $record = New-Object PSCustomObject -Property @{
                Time    = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Level   = $levelText
                Log     = $evt.LogName
                Source  = $evt.ProviderName
                EventID = $evt.Id
                Message = $evt.Message
            }
            # Enforce column order (PSCustomObject from hashtable has
            # undefined order on 5.1; Select-Object fixes it).
            $record = $record | Select-Object Time, Level, Log, Source, EventID, Message

            $output.Add($record)
        }
    }
    end { return @($output.ToArray()) }
}

function Get-LevelName {
    <#
    .SYNOPSIS  Maps a numeric event level to its human-readable name.
    .DESCRIPTION
        Windows Event Log levels:
          0 = LogAlways, 1 = Critical, 2 = Error,
          3 = Warning,   4 = Information, 5 = Verbose.
        Unknown values are returned as "Level-<n>".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$LevelValue
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
