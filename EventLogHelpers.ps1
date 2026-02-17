#Requires -Version 5.1

<#
.SYNOPSIS
    Helper functions for Get-MergedEventLogs.ps1.

.DESCRIPTION
    Contains the core logic extracted into individually-testable
    functions.  Dot-sourced by the main script.
#>

Set-StrictMode -Version Latest

function Assert-DateRange {
    <#
    .SYNOPSIS  Validates that -After is earlier than -Before.
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
        Produces an XPath expression that selects events matching the
        specified severity levels within a time window expressed as
        millisecond offsets from "now" (using the timediff function
        understood by the Windows Event Log engine).
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

    # timediff(@SystemTime) returns the number of milliseconds between
    # "now" and the event timestamp.  A larger timediff value means the
    # event is older.
    #   - Events AFTER  $After  -> timediff <= (now - After)  in ms
    #   - Events BEFORE $Before -> timediff >= (now - Before) in ms
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
    #>
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

function Get-LevelName {
    <#
    .SYNOPSIS  Maps a numeric event level to its display name.
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
