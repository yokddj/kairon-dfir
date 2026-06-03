from pathlib import PureWindowsPath


def evtx_subcategory(path: str | None) -> str | None:
    if not path:
        return None
    name = PureWindowsPath(path).name.lower()
    mapping = {
        "security.evtx": "Security",
        "system.evtx": "System",
        "application.evtx": "Application",
        "microsoft-windows-powershell%4operational.evtx": "PowerShell",
        "microsoft-windows-windows defender%4operational.evtx": "Defender",
        "microsoft-windows-wmi-activity%4operational.evtx": "WMI Activity",
        "microsoft-windows-bits-client%4operational.evtx": "BITS Client",
        "microsoft-windows-wlan-autoconfig%4operational.evtx": "WLAN AutoConfig",
        "microsoft-windows-terminalservices-local session manager%4operational.evtx": "RDP/TerminalServices",
        "microsoft-windows-taskscheduler%4operational.evtx": "TaskScheduler",
        "microsoft-windows-sysmon%4operational.evtx": "Sysmon",
    }
    return mapping.get(name)

