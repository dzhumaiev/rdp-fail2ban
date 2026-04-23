#Requires -RunAsAdministrator
param(
    [switch]$task,
    [switch]$install,
    [string]$delip
)
Set-StrictMode -Version Latest

# === Path setup ===
$BasePath = 'C:\Program Files (x86)\rdp_guard'
$LogDir = Join-Path $BasePath 'logs'
$ScriptName = 'rdpf2b.ps1'
$ScriptPath = Join-Path $BasePath $ScriptName
$CurrentScript = $MyInvocation.MyCommand.Definition

# === Files ===
$DateStamp = Get-Date -Format 'yyyyMMdd'
$LogFile = Join-Path $LogDir "rdpf2b_$DateStamp.log"
$BlockedIPsDB = Join-Path $BasePath 'blocked_ips.db'
$LockFile = Join-Path $BasePath 'rdpf2b.lock'

# === Configuration ===
# Number of failed login attempts from an IP before it gets blocked.
# Attempts are counted within the last $FailWindowMinutes minutes across all runs.
$FailThreshold = 5
$FailWindowMinutes = 30
$FailCountDB = Join-Path $BasePath 'fail_counts.json'

# === Logging ===
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "[MM/dd/yy HH:mm:ss]"
    $logEntry = "$timestamp $Message"
    Add-Content -Path $LogFile -Value $logEntry
}

# === Install structure ===
function Install-ScriptStructure {
    try {
        if (!(Test-Path $BasePath)) {
            New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
            Write-Host "Created directory: $BasePath"
        }

        if (!(Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            Write-Host "Created directory: $LogDir"
        }

        Copy-Item -Path $CurrentScript -Destination $ScriptPath -Force
        Write-Host "Script copied to: $ScriptPath"

        $CleanupScriptPath = Join-Path $BasePath 'cleanup_logs.ps1'
        $cleanupScript = @"
`$LogDir = '$LogDir'
`$limit = (Get-Date).AddDays(-30)
`$logFiles = Get-ChildItem -Path `$LogDir -File -Recurse | Where-Object { `$_.LastWriteTime -lt `$limit }
foreach (`$file in `$logFiles) {
    try {
        Remove-Item -Path `$file.FullName -Force
    } catch {}
}
"@
        Set-Content -Path $CleanupScriptPath -Value $cleanupScript -Encoding UTF8
        Write-Host "Cleanup script created at: $CleanupScriptPath"

        if ($CurrentScript -ne $ScriptPath) {
            Write-Host "Deleting installer script: $CurrentScript"
            Start-Sleep -Seconds 1
            Remove-Item -Path $CurrentScript -Force
        }
    } catch {
        Write-Error "Installation failed: $_"
    }
}

# === Task registration ===
function Register-ScheduledTasks {
    Write-Log "Creating scheduled tasks..."

    $CleanupScriptPath = Join-Path $BasePath 'cleanup_logs.ps1'
    $psExe = 'powershell.exe'
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    # --- Task 1: Main RDP fail2ban logic (every 10 minutes) ---
    $action1 = New-ScheduledTaskAction `
        -Execute $psExe `
        -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$ScriptPath`""
    $trigger1 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 10) -Once -At (Get-Date)
    $settings1 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask `
        -TaskName "RDP fail2ban" `
        -Action $action1 `
        -Trigger $trigger1 `
        -Principal $principal `
        -Settings $settings1 `
        -Force | Out-Null
    Write-Log "Task 'RDP fail2ban' registered."

    # --- Task 2: Clear EventViewer Security Log (weekly, Sunday) ---
    $action2 = New-ScheduledTaskAction `
        -Execute $psExe `
        -Argument "-ExecutionPolicy Bypass -NonInteractive -Command `"Clear-EventLog -LogName Security`""
    $trigger2 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00"
    $settings2 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask `
        -TaskName "Clear EventViewer Security Log" `
        -Action $action2 `
        -Trigger $trigger2 `
        -Principal $principal `
        -Settings $settings2 `
        -Force | Out-Null
    Write-Log "Task 'Clear EventViewer Security Log' registered."

    # --- Task 3: Log Cleanup (daily) ---
    $action3 = New-ScheduledTaskAction `
        -Execute $psExe `
        -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$CleanupScriptPath`""
    $trigger3 = New-ScheduledTaskTrigger -Daily -At "02:00"
    $settings3 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask `
        -TaskName "RDP Log Cleanup" `
        -Action $action3 `
        -Trigger $trigger3 `
        -Principal $principal `
        -Settings $settings3 `
        -Force | Out-Null
    Write-Log "Task 'RDP Log Cleanup' registered."

    Clear-EventLog -LogName Security
    Write-Log "All scheduled tasks created successfully."
}

# === Add IPs to the firewall rule ===
function Add-ToFirewallRule {
    param (
        [string[]]$IPs,
        [string]$RuleName = "BlockedIPsRule"
    )

    if (-not $IPs -or $IPs.Count -eq 0) {
        Write-Log "No IPs provided to Add-ToFirewallRule."
        return
    }

    $existingIPs = @()
    if (Test-Path $BlockedIPsDB) {
        $existingIPs = @(Get-Content $BlockedIPsDB | Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}$" })
    }

    function IsValidIPv4($ip) {
        if ($ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
            return ([int]$matches[1] -le 255) -and ([int]$matches[2] -le 255) -and `
                   ([int]$matches[3] -le 255) -and ([int]$matches[4] -le 255)
        }
        return $false
    }

    $newIPs = @()
    foreach ($ip in $IPs) {
        $ip = $ip.Trim()
        if ($ip -and (IsValidIPv4 $ip) -and ($ip -notin $existingIPs)) {
            $newIPs += $ip
        }
    }

    if ($newIPs.Count -eq 0) {
        Write-Log "No new IPs to add to firewall."
        return
    }

    $allIPs = @($existingIPs) + @($newIPs)

    if ($allIPs.Count -gt 999) {
        Write-Log "IP count ($($allIPs.Count)) exceeds 999. Resetting the firewall rule and database."
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        Write-Log "Removed existing firewall rule '$RuleName'."
        $newIPs | Set-Content -Path $BlockedIPsDB -Encoding UTF8
        Write-Log "IP database reset. It now contains only the $($newIPs.Count) new IPs."
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $newIPs -Profile Any -Enabled True | Out-Null
        Write-Log "Recreated firewall rule '$RuleName' with new IPs: $($newIPs -join ', ')"
    } else {
        $newIPs | Out-File -FilePath $BlockedIPsDB -Append -Encoding UTF8
        $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

        if (-not $rule) {
            Write-Log "Creating new firewall rule: $RuleName"
            New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $allIPs -Profile Any -Enabled True | Out-Null
        } else {
            try {
                Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $allIPs
                Write-Log "Added IPs to ${RuleName}: $($newIPs -join ', ')"
            } catch {
                Write-Log "Failed to update firewall rule: $_"
            }
        }
    }
}

# === Remove IP from firewall and database ===
function Remove-IPFromFirewallRule {
    param (
        [string]$IPToRemove,
        [string]$RuleName = "BlockedIPsRule"
    )

    if ([string]::IsNullOrWhiteSpace($IPToRemove)) {
        Write-Log "Error: No valid IP address specified for removal."
        return
    }
    $IPToRemove = $IPToRemove.Trim()

    if (-not (Test-Path $BlockedIPsDB)) {
        Write-Log "Blocked IP database not found: $BlockedIPsDB"
        return
    }

    $allIPs = @(Get-Content $BlockedIPsDB |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}$" } |
        Sort-Object -Unique)
    $newIPs = @($allIPs | Where-Object { $_ -ne $IPToRemove })

    if ($allIPs.Count -eq $newIPs.Count) {
        Write-Log "IP $IPToRemove not found in database file. Proceeding to check firewall rule just in case."
    } else {
        $newIPs | Set-Content -Path $BlockedIPsDB -Encoding UTF8
        Write-Log "Removed IP $IPToRemove from database file."
    }

    $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($rule) {
        try {
            if ($newIPs.Count -eq 0) {
                Remove-NetFirewallRule -DisplayName $RuleName
                Write-Log "No IPs left in database - firewall rule '$RuleName' removed."
            } else {
                Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $newIPs
                Write-Log "Updated firewall rule '$RuleName' after removing IP $IPToRemove."
            }
        } catch {
            Write-Log ("Error updating firewall rule: {0}" -f $_)
        }
    } else {
        Write-Log "Firewall rule '$RuleName' not found."
    }
}

# === Load fail count database ===
function Get-FailCounts {
    if (Test-Path $FailCountDB) {
        try {
            $raw = Get-Content $FailCountDB -Raw -Encoding UTF8
            if ($raw) {
                # -AsHashtable requires PS6+. Manually convert for PS5.1 compatibility.
                $obj = $raw | ConvertFrom-Json
                $ht = @{}
                foreach ($prop in $obj.PSObject.Properties) {
                    $ht[$prop.Name] = @($prop.Value)
                }
                return $ht
            }
        } catch {
            Write-Log "Warning: Could not parse fail_counts.json, starting fresh. Error: $_"
        }
    }
    return @{}
}

# === Save fail count database ===
function Save-FailCounts {
    param ([hashtable]$Counts)
    try {
        $Counts | ConvertTo-Json -Depth 3 | Set-Content -Path $FailCountDB -Encoding UTF8
    } catch {
        Write-Log "Warning: Could not save fail_counts.json: $_"
    }
}

# === Purge stale entries outside the fail window ===
function Purge-StaleFailCounts {
    param ([hashtable]$Counts)
    $cutoff = (Get-Date).AddMinutes(-$FailWindowMinutes).ToString('o')
    $staleKeys = @()
    foreach ($key in $Counts.Keys) {
        # Each entry is a list of ISO timestamp strings
        $fresh = @($Counts[$key] | Where-Object { $_ -ge $cutoff })
        if ($fresh.Count -eq 0) {
            $staleKeys += $key
        } else {
            $Counts[$key] = $fresh
        }
    }
    foreach ($key in $staleKeys) {
        $Counts.Remove($key)
    }
    return $Counts
}

# === Main RDP fail2ban logic ===
function Run-RDPFail2Ban {
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    if (!(Test-Path $BlockedIPsDB)) {
        New-Item -Path $BlockedIPsDB -ItemType File -Force | Out-Null
    }

    $logName = "Security"
    $eventId = 4625
    $startTime = (Get-Date).AddMinutes(-11)
    $allowedUsers = (Get-LocalUser | Where-Object { $_.Enabled }).Name

    # Load and purge the persistent fail count database
    $failCounts = Get-FailCounts
    $failCounts = Purge-StaleFailCounts -Counts $failCounts

    try {
        $maxRetries = 3
        $retryCount = 0
        $events = $null
        $eventsLoaded = $false
        while (-not $eventsLoaded -and $retryCount -lt $maxRetries) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = $logName
                    Id        = $eventId
                    StartTime = $startTime
                } -ErrorAction Stop
                $eventsLoaded = $true
            } catch {
                # "No events found" is a normal empty result, not a real error - don't retry it.
                if ($_.Exception.Message -match 'No events were found|events') {
                    $eventsLoaded = $true
                    $events = $null
                } else {
                    $retryCount++
                    Write-Log "Retry $retryCount/$maxRetries for Get-WinEvent: $_"
                    Start-Sleep -Seconds 5
                }
            }
        }

        if ($null -eq $events) {
            Write-Log "No failed login events in the last 11 minutes."
            Save-FailCounts -Counts $failCounts
            return
        }

        # Tally new failures into the fail count database
        foreach ($event in $events) {
            $message = $event.Message
            $ipMatches = [regex]::Matches($message, "\b\d{1,3}(\.\d{1,3}){3}\b") | ForEach-Object { $_.Value }
            $userName = ($event.Properties[5]).Value
            $eventTime = $event.TimeCreated.ToString('o')

            if ($allowedUsers -notcontains $userName) {
                foreach ($ip in $ipMatches) {
                    if (-not $failCounts.ContainsKey($ip)) {
                        $failCounts[$ip] = @()
                    }
                    # Only record this event timestamp if not already counted
                    if ($failCounts[$ip] -notcontains $eventTime) {
                        $failCounts[$ip] += $eventTime
                        Write-Log "Failed attempt from $ip (user: $userName) — total in window: $($failCounts[$ip].Count)/$FailThreshold"
                    }
                }
            }
        }

        # Determine which IPs have crossed the threshold
        $ipsToBlock = New-Object System.Collections.Generic.List[string]
        foreach ($ip in $failCounts.Keys) {
            if ($failCounts[$ip].Count -ge $FailThreshold) {
                $ipsToBlock.Add($ip)
                Write-Log "Threshold reached for $ip ($($failCounts[$ip].Count) failures in ${FailWindowMinutes}min window) — queuing for block."
            }
        }

        if ($ipsToBlock.Count -gt 0) {
            Add-ToFirewallRule -IPs $ipsToBlock
            # Remove blocked IPs from fail count database so they don't keep accumulating
            foreach ($ip in $ipsToBlock) {
                $failCounts.Remove($ip)
            }
        } else {
            Write-Log "No IPs have reached the block threshold ($FailThreshold failures in ${FailWindowMinutes}min)."
        }

    } catch {
        Write-Log ("Error processing event log: {0}" -f $_)
    } finally {
        Save-FailCounts -Counts $failCounts
    }
}

# === Main execution ===
if (Test-Path $LockFile) {
    Write-Log "Another instance of the script is running. Exiting."
    exit
}
New-Item -Path $LockFile -ItemType File -Force | Out-Null
try {
    if ($install) {
        Install-ScriptStructure
    } elseif ($task) {
        Register-ScheduledTasks
    } elseif ($delip) {
        Remove-IPFromFirewallRule -IPToRemove $delip
    } else {
        Run-RDPFail2Ban
    }
} finally {
    Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
}
