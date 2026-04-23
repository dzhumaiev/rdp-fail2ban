# === Configuration ===
$hookUrl = "DISCORD URL"
$BlockedDbPath = 'C:\Program Files (x86)\rdp_guard\blocked_ips.db'
$SentDbPath = 'C:\Program Files (x86)\rdp_guard\sent_to_discord.txt'

# 1. Load the current blocked IPs (The Reality)
if (!(Test-Path $BlockedDbPath)) { 
    $currentBlocked = @() 
} else {
    $currentBlocked = Get-Content $BlockedDbPath | Where-Object { $_ -ne "" }
}

# 2. Load IPs we previously notified about (The Memory)
$alreadySent = @()
if (Test-Path $SentDbPath) {
    $alreadySent = Get-Content $SentDbPath | Where-Object { $_ -ne "" }
}

# 3. Find NEWLY BLOCKED (In BlockedDb, but not in SentDb)
$newlyBlocked = $currentBlocked | Where-Object { $_ -notin $alreadySent }

# 4. Find NEWLY UNBLOCKED (In SentDb, but no longer in BlockedDb)
$newlyUnblocked = $alreadySent | Where-Object { $_ -notin $currentBlocked }

# --- Process New Blocks ---
foreach ($ip in $newlyBlocked) {
    $body = @{ content = " **IP Blocked:** $ip on Server: $($env:COMPUTERNAME)" } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $hookUrl -Method Post -Body $body -ContentType "application/json"
        Add-Content -Path $SentDbPath -Value $ip
        Start-Sleep -Milliseconds 500
    } catch { Write-Error "Failed block notification for $ip" }
}

# --- Process New Unblocks ---
if ($newlyUnblocked) {
    $updatedSentList = New-Object System.Collections.Generic.List[string]
    $alreadySent | ForEach-Object { if ($_ -notin $newlyUnblocked) { $updatedSentList.Add($_) } }

    foreach ($ip in $newlyUnblocked) {
        $body = @{ content = " **IP Unblocked/Deleted:** $ip on Server: $($env:COMPUTERNAME)" } | ConvertTo-Json
        try {
            Invoke-RestMethod -Uri $hookUrl -Method Post -Body $body -ContentType "application/json"
            Start-Sleep -Milliseconds 500
        } catch { Write-Error "Failed unblock notification for $ip" }
    }
    
    # Update the Memory file to remove the unblocked IPs
    $updatedSentList | Set-Content -Path $SentDbPath
}
