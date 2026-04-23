$LogDir = 'C:\Program Files (x86)\rdp_guard\logs'
$limit = (Get-Date).AddDays(-30)
$logFiles = Get-ChildItem -Path $LogDir -File -Recurse | Where-Object { $_.LastWriteTime -lt $limit }
foreach ($file in $logFiles) {
    try {
        Remove-Item -Path $file.FullName -Force
    } catch {}
}
