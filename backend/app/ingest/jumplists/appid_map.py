from __future__ import annotations


APP_ID_MAP: dict[str, str] = {
    "microsoft.windows.explorer": "Windows Explorer",
    "explorer.exe": "Windows Explorer",
    "microsoft.microsoftedge.stable": "Microsoft Edge",
    "msedge.exe": "Microsoft Edge",
    "chrome.exe": "Google Chrome",
    "google chrome": "Google Chrome",
    "brave.exe": "Brave",
    "firefox.exe": "Mozilla Firefox",
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "acrord32.exe": "Adobe Reader",
    "notepad.exe": "Notepad",
    "mspaint.exe": "Paint",
    "vlc.exe": "VLC media player",
    "7zfm.exe": "7-Zip",
    "winrar.exe": "WinRAR",
    "powershell.exe": "Windows PowerShell",
    "pwsh.exe": "PowerShell",
    "cmd.exe": "Command Prompt",
    "teams.exe": "Microsoft Teams",
    "onedrive.exe": "OneDrive",
}


def resolve_app_id_name(app_id: str | None, description: str | None = None, app_name: str | None = None) -> str | None:
    for candidate in (app_name, description):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    if not app_id:
        return None
    normalized = str(app_id).strip().lower()
    return APP_ID_MAP.get(normalized) or str(app_id).strip()
