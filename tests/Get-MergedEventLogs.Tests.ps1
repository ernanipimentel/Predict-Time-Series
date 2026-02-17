#Requires -Modules Pester

<#
.SYNOPSIS
    Pester 5 tests for Get-MergedEventLogs and its helper functions.

.DESCRIPTION
    All Windows Event Log calls are mocked so the tests can run on
    any platform (including Linux CI runners) without access to real
    event logs.

.NOTES
    Run with:  Invoke-Pester -Path .\tests\Get-MergedEventLogs.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Dot-source the standalone helpers file so every function is
    # available in scope for individual testing.
    . "$PSScriptRoot\..\EventLogHelpers.ps1"

    # ── Mock-event factory ───────────────────────────────────────────
    function New-MockEvent {
        <#
        .SYNOPSIS  Creates a lightweight object that mimics the
                   properties of a System.Diagnostics.Eventing.Reader.EventLogRecord.
        #>
        param(
            [datetime]$TimeCreated,
            [int]$Level,
            [string]$LevelDisplayName,
            [string]$LogName,
            [string]$ProviderName,
            [int]$Id,
            [string]$Message
        )

        [PSCustomObject]@{
            TimeCreated      = $TimeCreated
            Level            = $Level
            LevelDisplayName = $LevelDisplayName
            LogName          = $LogName
            ProviderName     = $ProviderName
            Id               = $Id
            Message          = $Message
        }
    }

    # ── Shared sample events ─────────────────────────────────────────
    $script:now = Get-Date '2026-02-17 12:00:00'

    $script:sampleEvents = @(
        # Application - Error (oldest)
        New-MockEvent -TimeCreated $now.AddHours(-5) -Level 2 `
            -LevelDisplayName 'Error' -LogName 'Application' `
            -ProviderName 'AppSource' -Id 1001 `
            -Message "Application error occurred.`nSee details below."

        # Security - Warning
        New-MockEvent -TimeCreated $now.AddHours(-3) -Level 3 `
            -LevelDisplayName 'Warning' -LogName 'Security' `
            -ProviderName 'SecSource' -Id 4625 `
            -Message 'Logon failure: unknown user name or bad password.'

        # System - Critical (newest)
        New-MockEvent -TimeCreated $now.AddHours(-1) -Level 1 `
            -LevelDisplayName 'Critical' -LogName 'System' `
            -ProviderName 'SysSource' -Id 41 `
            -Message 'The system has rebooted without cleanly shutting down.'

        # Application - Warning
        New-MockEvent -TimeCreated $now.AddHours(-2) -Level 3 `
            -LevelDisplayName 'Warning' -LogName 'Application' `
            -ProviderName 'AppSource' -Id 1002 `
            -Message 'Application pool recycled.'

        # System - Error
        New-MockEvent -TimeCreated $now.AddHours(-4) -Level 2 `
            -LevelDisplayName 'Error' -LogName 'System' `
            -ProviderName 'SysSource' -Id 7034 `
            -Message 'The Windows Search service terminated unexpectedly.'
    )
}

# =====================================================================
# 1.  Assert-DateRange
# =====================================================================
Describe 'Assert-DateRange' {

    It 'Does not throw when After is earlier than Before' {
        { Assert-DateRange -After '2026-01-01' -Before '2026-02-01' } |
            Should -Not -Throw
    }

    It 'Throws ArgumentException when After equals Before' {
        $date = Get-Date '2026-02-01'
        { Assert-DateRange -After $date -Before $date } |
            Should -Throw '*must be earlier*'
    }

    It 'Throws ArgumentException when After is later than Before' {
        { Assert-DateRange -After '2026-03-01' -Before '2026-02-01' } |
            Should -Throw '*must be earlier*'
    }
}

# =====================================================================
# 2.  Assert-ExportPath
# =====================================================================
Describe 'Assert-ExportPath' {

    It 'Does not throw when the parent directory exists' {
        # Use the temp directory which always exists.
        $path = Join-Path ([System.IO.Path]::GetTempPath()) 'test-export.csv'
        { Assert-ExportPath -Path $path } | Should -Not -Throw
    }

    It 'Throws DirectoryNotFoundException when parent does not exist' {
        { Assert-ExportPath -Path '/no/such/directory/file.csv' } |
            Should -Throw '*does not exist*'
    }

    It 'Does not throw when path has no parent component' {
        # A bare filename like "out.csv" has no parent to validate.
        { Assert-ExportPath -Path 'output.csv' } | Should -Not -Throw
    }
}

# =====================================================================
# 3.  Get-LevelName
# =====================================================================
Describe 'Get-LevelName' {

    It 'Returns "Critical" for level 1'    { Get-LevelName -LevelValue 1 | Should -Be 'Critical' }
    It 'Returns "Error" for level 2'       { Get-LevelName -LevelValue 2 | Should -Be 'Error' }
    It 'Returns "Warning" for level 3'     { Get-LevelName -LevelValue 3 | Should -Be 'Warning' }
    It 'Returns "Information" for level 4'  { Get-LevelName -LevelValue 4 | Should -Be 'Information' }
    It 'Returns "Verbose" for level 5'     { Get-LevelName -LevelValue 5 | Should -Be 'Verbose' }
    It 'Returns "LogAlways" for level 0'   { Get-LevelName -LevelValue 0 | Should -Be 'LogAlways' }
    It 'Returns "Level-99" for unknown 99' { Get-LevelName -LevelValue 99 | Should -Be 'Level-99' }
}

# =====================================================================
# 4.  Build-EventXPathFilter
# =====================================================================
Describe 'Build-EventXPathFilter' {

    It 'Includes all three severity levels by default' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Match 'Level=1'
        $xpath | Should -Match 'Level=2'
        $xpath | Should -Match 'Level=3'
    }

    It 'Does not include Level=4 (Information)' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Not -Match 'Level=4'
    }

    It 'Respects custom level list' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date) `
                                         -Levels @(2)
        $xpath | Should -Match 'Level=2'
        $xpath | Should -Not -Match 'Level=1'
        $xpath | Should -Not -Match 'Level=3'
    }

    It 'Contains timediff clauses' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Match 'timediff\(@SystemTime\)'
    }

    It 'Returns a non-empty string' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Not -BeNullOrEmpty
    }
}

# =====================================================================
# 5.  ConvertTo-EventRecord
# =====================================================================
Describe 'ConvertTo-EventRecord' {

    It 'Converts mock events to PSCustomObjects with correct properties' {
        $records = ConvertTo-EventRecord -Events $script:sampleEvents
        $records | Should -HaveCount $script:sampleEvents.Count

        $first = $records[0]
        $first.PSObject.Properties.Name | Should -Contain 'Time'
        $first.PSObject.Properties.Name | Should -Contain 'Level'
        $first.PSObject.Properties.Name | Should -Contain 'Log'
        $first.PSObject.Properties.Name | Should -Contain 'Source'
        $first.PSObject.Properties.Name | Should -Contain 'EventID'
        $first.PSObject.Properties.Name | Should -Contain 'Message'
    }

    It 'Formats Time as yyyy-MM-dd HH:mm:ss' {
        $records = ConvertTo-EventRecord -Events $script:sampleEvents
        $records[0].Time | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
    }

    It 'Uses LevelDisplayName when available' {
        $records = ConvertTo-EventRecord -Events $script:sampleEvents
        $records[0].Level | Should -Be 'Error'
    }

    It 'Falls back to Get-LevelName when LevelDisplayName is empty' {
        $evt = New-MockEvent -TimeCreated (Get-Date) -Level 1 `
            -LevelDisplayName '' -LogName 'System' `
            -ProviderName 'Test' -Id 1 -Message 'msg'

        $records = ConvertTo-EventRecord -Events @($evt)
        $records[0].Level | Should -Be 'Critical'
    }

    It 'Preserves full multi-line message' {
        $records = ConvertTo-EventRecord -Events $script:sampleEvents
        # The first sample event has a two-line message.
        $records[0].Message | Should -Match "`n"
    }

    It 'Returns empty array for empty input' {
        $records = ConvertTo-EventRecord -Events @()
        $records | Should -HaveCount 0
    }
}

# =====================================================================
# 6.  Get-FilteredEvents (mocked Get-WinEvent)
# =====================================================================
Describe 'Get-FilteredEvents' {

    BeforeAll {
        # Mock Get-WinEvent to return events from our sample set,
        # filtered by LogName, without touching real Windows logs.
        Mock Get-WinEvent {
            $logName = $LogName               # bound by -LogName
            $max     = $MaxEvents             # bound by -MaxEvents
            $matched = $script:sampleEvents | Where-Object { $_.LogName -eq $logName }
            if (-not $matched) {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            }
            return @($matched | Select-Object -First $max)
        }
    }

    It 'Returns only Application events when LogName is Application' {
        $results = Get-FilteredEvents -LogName 'Application' `
                        -After $script:now.AddHours(-6) `
                        -Before $script:now
        $results | ForEach-Object { $_.LogName | Should -Be 'Application' }
    }

    It 'Returns only System events when LogName is System' {
        $results = Get-FilteredEvents -LogName 'System' `
                        -After $script:now.AddHours(-6) `
                        -Before $script:now
        $results | ForEach-Object { $_.LogName | Should -Be 'System' }
    }

    It 'Returns only Security events when LogName is Security' {
        $results = Get-FilteredEvents -LogName 'Security' `
                        -After $script:now.AddHours(-6) `
                        -Before $script:now
        $results | ForEach-Object { $_.LogName | Should -Be 'Security' }
    }

    It 'Respects MaxEvents limit' {
        $results = Get-FilteredEvents -LogName 'Application' `
                        -After $script:now.AddHours(-6) `
                        -Before $script:now `
                        -MaxEvents 1
        $results | Should -HaveCount 1
    }

    It 'Throws when no events match' {
        { Get-FilteredEvents -LogName 'NonExistent' `
                -After $script:now.AddHours(-6) `
                -Before $script:now } |
            Should -Throw '*No events were found*'
    }

    It 'Calls Get-WinEvent with correct parameters' {
        Get-FilteredEvents -LogName 'System' `
            -After $script:now.AddHours(-6) `
            -Before $script:now `
            -MaxEvents 50

        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter {
            $LogName   -eq 'System' -and
            $MaxEvents -eq 50
        }
    }
}

# =====================================================================
# 7.  Test-AdminPrivilege
# =====================================================================
Describe 'Test-AdminPrivilege' {

    It 'Returns a boolean value' {
        $result = Test-AdminPrivilege
        $result | Should -BeOfType [bool]
    }
}

# =====================================================================
# 8.  Chronological sorting (integration-style)
# =====================================================================
Describe 'Chronological sorting of merged events' {

    It 'Sorts events from oldest to newest after merging' {
        $sorted  = $script:sampleEvents | Sort-Object -Property TimeCreated
        $records = ConvertTo-EventRecord -Events $sorted

        for ($i = 1; $i -lt $records.Count; $i++) {
            $records[$i].Time | Should -BeGreaterOrEqual $records[$i - 1].Time
        }
    }

    It 'Produces correct chronological order across all three logs' {
        $sorted  = $script:sampleEvents | Sort-Object -Property TimeCreated
        $records = ConvertTo-EventRecord -Events $sorted

        # Expected order by TimeCreated (hours before $now):
        #   -5h Application Error
        #   -4h System Error
        #   -3h Security Warning
        #   -2h Application Warning
        #   -1h System Critical
        $records[0].Log | Should -Be 'Application'
        $records[0].Level | Should -Be 'Error'

        $records[1].Log | Should -Be 'System'
        $records[1].Level | Should -Be 'Error'

        $records[2].Log | Should -Be 'Security'
        $records[2].Level | Should -Be 'Warning'

        $records[3].Log | Should -Be 'Application'
        $records[3].Level | Should -Be 'Warning'

        $records[4].Log | Should -Be 'System'
        $records[4].Level | Should -Be 'Critical'
    }

    It 'Includes events from all three log sources' {
        $sorted  = $script:sampleEvents | Sort-Object -Property TimeCreated
        $records = ConvertTo-EventRecord -Events $sorted
        $logs    = $records | Select-Object -ExpandProperty Log -Unique | Sort-Object
        $logs | Should -Contain 'Application'
        $logs | Should -Contain 'Security'
        $logs | Should -Contain 'System'
    }
}

# =====================================================================
# 9.  Informational events are excluded
# =====================================================================
Describe 'Informational events are excluded' {

    It 'XPath filter does not match Information level (4)' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Not -Match 'Level=4'
    }

    It 'XPath filter does not match LogAlways level (0)' {
        $xpath = Build-EventXPathFilter -After (Get-Date).AddHours(-1) `
                                         -Before (Get-Date)
        $xpath | Should -Not -Match 'Level=0'
    }

    It 'Only keeps Critical, Error, and Warning events in sample data' {
        # Our sample set intentionally has no Information-level events.
        $allowedLevels = @(1, 2, 3)
        $script:sampleEvents | ForEach-Object {
            $_.Level | Should -BeIn $allowedLevels
        }
    }
}

# =====================================================================
# 10. CSV / JSON export paths (mocked filesystem)
# =====================================================================
Describe 'Export functionality' {

    BeforeAll {
        $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) `
                                    "PesterEventLogTests_$(Get-Random)"
        New-Item -Path $script:tmpDir -ItemType Directory -Force | Out-Null
    }

    AfterAll {
        Remove-Item -Path $script:tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context 'CSV export' {

        It 'Creates a valid CSV file' {
            $csvPath = Join-Path $script:tmpDir 'test-export.csv'
            $sorted  = $script:sampleEvents | Sort-Object TimeCreated
            $records = ConvertTo-EventRecord -Events $sorted

            $records | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            Test-Path $csvPath | Should -Be $true
            $imported = Import-Csv -Path $csvPath
            $imported | Should -HaveCount $records.Count
        }

        It 'Preserves all columns in CSV' {
            $csvPath = Join-Path $script:tmpDir 'test-columns.csv'
            $sorted  = $script:sampleEvents | Sort-Object TimeCreated
            $records = ConvertTo-EventRecord -Events $sorted

            $records | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            $imported = Import-Csv -Path $csvPath
            $imported[0].PSObject.Properties.Name | Should -Contain 'Time'
            $imported[0].PSObject.Properties.Name | Should -Contain 'Level'
            $imported[0].PSObject.Properties.Name | Should -Contain 'Log'
            $imported[0].PSObject.Properties.Name | Should -Contain 'Source'
            $imported[0].PSObject.Properties.Name | Should -Contain 'EventID'
            $imported[0].PSObject.Properties.Name | Should -Contain 'Message'
        }
    }

    Context 'JSON export' {

        It 'Creates a valid JSON file' {
            $jsonPath = Join-Path $script:tmpDir 'test-export.json'
            $sorted   = $script:sampleEvents | Sort-Object TimeCreated
            $records  = ConvertTo-EventRecord -Events $sorted

            $records | ConvertTo-Json -Depth 3 |
                Set-Content -Path $jsonPath -Encoding UTF8

            Test-Path $jsonPath | Should -Be $true
            $content  = Get-Content -Path $jsonPath -Raw
            $imported = $content | ConvertFrom-Json
            $imported | Should -HaveCount $records.Count
        }

        It 'Preserves field values through JSON round-trip' {
            $jsonPath = Join-Path $script:tmpDir 'test-roundtrip.json'
            $sorted   = $script:sampleEvents | Sort-Object TimeCreated
            $records  = ConvertTo-EventRecord -Events $sorted

            $records | ConvertTo-Json -Depth 3 |
                Set-Content -Path $jsonPath -Encoding UTF8

            $imported = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            $imported[0].Level   | Should -Be $records[0].Level
            $imported[0].Log     | Should -Be $records[0].Log
            $imported[0].EventID | Should -Be $records[0].EventID
        }
    }
}

# =====================================================================
# 11. Edge cases
# =====================================================================
Describe 'Edge cases' {

    It 'Handles a single event correctly' {
        $single  = @($script:sampleEvents[0])
        $records = ConvertTo-EventRecord -Events $single
        $records | Should -HaveCount 1
        $records[0].Log | Should -Be 'Application'
    }

    It 'Handles events with identical timestamps' {
        $ts = Get-Date '2026-02-17 10:00:00'
        $dupes = @(
            New-MockEvent -TimeCreated $ts -Level 2 `
                -LevelDisplayName 'Error' -LogName 'System' `
                -ProviderName 'Src1' -Id 100 -Message 'First'
            New-MockEvent -TimeCreated $ts -Level 3 `
                -LevelDisplayName 'Warning' -LogName 'Application' `
                -ProviderName 'Src2' -Id 200 -Message 'Second'
        )
        $sorted  = $dupes | Sort-Object TimeCreated
        $records = ConvertTo-EventRecord -Events $sorted
        $records | Should -HaveCount 2
        $records[0].Time | Should -Be $records[1].Time
    }

    It 'Handles events with null/empty messages gracefully' {
        $evt = New-MockEvent -TimeCreated (Get-Date) -Level 2 `
            -LevelDisplayName 'Error' -LogName 'Application' `
            -ProviderName 'Src' -Id 1 -Message ''

        $records = ConvertTo-EventRecord -Events @($evt)
        $records[0].Message | Should -Be ''
    }

    It 'Handles very long messages without truncation in records' {
        $longMsg = 'A' * 10000
        $evt = New-MockEvent -TimeCreated (Get-Date) -Level 2 `
            -LevelDisplayName 'Error' -LogName 'Application' `
            -ProviderName 'Src' -Id 1 -Message $longMsg

        $records = ConvertTo-EventRecord -Events @($evt)
        $records[0].Message.Length | Should -Be 10000
    }

    It 'Build-EventXPathFilter works at date-range boundaries' {
        $after  = Get-Date '2026-02-17 00:00:00'
        $before = Get-Date '2026-02-17 00:00:01'
        $xpath  = Build-EventXPathFilter -After $after -Before $before
        $xpath | Should -Not -BeNullOrEmpty
    }
}
