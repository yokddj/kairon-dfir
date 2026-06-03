from pathlib import Path
import re

import yaml

from app.ingest.eztools.detector import detect_eztool_output
from app.ingest.browser.detector import classify_browser_artifact, looks_like_browser_artifact
from app.ingest.autoruns.helpers import looks_like_autoruns_artifact
from app.ingest.bits.helpers import looks_like_bits_artifact
from app.ingest.cloud_sync.helpers import looks_like_cloud_sync_artifact
from app.ingest.defender.helpers import looks_like_defender_artifact
from app.ingest.email.helpers import looks_like_email_artifact
from app.ingest.jumplists.helpers import looks_like_jumplist_artifact
from app.ingest.network.helpers import looks_like_network_artifact
from app.ingest.ntfs.helpers import looks_like_ntfs_artifact
from app.ingest.powershell.helpers import looks_like_powershell_artifact
from app.ingest.recycle_bin.helpers import looks_like_recycle_bin_artifact
from app.ingest.scheduled_tasks.helpers import looks_like_scheduled_task_artifact
from app.ingest.shellbags.helpers import looks_like_shellbags_artifact
from app.ingest.usb.helpers import looks_like_usb_artifact
from app.ingest.windows_ui.helpers import looks_like_windows_ui_artifact
from app.ingest.wmi.helpers import looks_like_wmi_artifact
from app.models.evidence import EvidenceType


VELOCIRAPTOR_HINTS = [
    "results/",
    "uploads/",
    ".json.index",
    "Windows.Triage.",
]

KAPE_NAME_MAP = {
    "PECmd": ("prefetch", "program_execution", "zimmerman"),
    "AmcacheParser": ("amcache", "execution_artifact", "zimmerman"),
    "AppCompatCacheParser": ("shimcache", "execution_artifact", "zimmerman"),
    "ShimCacheParser": ("shimcache", "execution_artifact", "zimmerman"),
    "RecentFileCache": ("appcompat", "execution_artifact", "zimmerman"),
    "RECmd": ("registry", "registry", "zimmerman"),
    "MFTECmd": ("mft", "filesystem", "zimmerman"),
    "JLECmd": ("jumplist", "file_folder_opening", "zimmerman"),
    "LECmd": ("lnk", "file_folder_opening", "zimmerman"),
    "EvtxECmd": ("evtx", "logon", "zimmerman"),
    "SBECmd": ("shellbags", "file_folder_opening", "zimmerman"),
    "RBCmd": ("recycle_bin", "filesystem", "zimmerman"),
    "WxTCmd": ("windows_timeline", "program_execution", "zimmerman"),
    "SrumECmd": ("srum", "network_activity", "zimmerman"),
    "ScheduledTasks": ("scheduled_task", "persistence", "csv"),
    "TaskScheduler": ("scheduled_task", "persistence", "csv"),
    "Defender": ("defender", "detection", "csv"),
    "WindowsDefender": ("defender", "detection", "csv"),
    "MicrosoftDefender": ("defender", "detection", "csv"),
    "DetectionHistory": ("defender", "detection", "defender_raw"),
    "MPLog": ("defender", "detection", "defender_raw"),
    "Threat": ("defender", "detection", "csv"),
    "Quarantine": ("defender", "detection", "raw"),
    "PowerShell": ("powershell", "powershell", "txt"),
    "PSReadLine": ("powershell", "powershell", "psreadline"),
    "ConsoleHost_history": ("powershell", "powershell", "psreadline"),
    "Transcript": ("powershell", "powershell", "transcript"),
    "ScriptBlock": ("powershell", "powershell", "csv"),
    "Hayabusa": ("evtx", "detection", "hayabusa"),
    "BrowserHistory": ("browser", "browser_usage", "generic_csv"),
    "TimelineExplorer": ("timeline", "timeline", "generic_csv"),
}

VELOCI_ARTIFACT_MAP = {
    "PsList_From_Pslist": ("process", "execution", "velociraptor"),
    "Netstat_NetstatEnriched": ("network", "network_activity", "velociraptor"),
    "PrefetchBinaries_Executables": ("prefetch", "program_execution", "velociraptor"),
    "AdaptiveServices_Executables": ("service", "persistence", "velociraptor"),
    "AdaptiveScheduledTasks_Commands": ("scheduled_tasks", "persistence", "velociraptor"),
    "LnkTargets_Targets": ("lnk", "file_folder_opening", "velociraptor"),
    "All Matches Metadata": ("filesystem", "filesystem", "velociraptor"),
    "SearchGlobs": ("collection_metadata", "collection_metadata", "velociraptor"),
}


def _structured_srum_parser(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return "srum_jsonl"
    if suffix == ".json":
        return "srum_json"
    if suffix == ".csv":
        return "srum_csv"
    return "srum_raw"


def _is_tool_console_log(path: Path) -> bool:
    lower_name = path.name.lower()
    if path.suffix.lower() != ".txt":
        return False
    if "consolelog" not in lower_name and "messages" not in lower_name:
        return False
    return any(
        token in lower_name
        for token in (
            "srumecmd",
            "evtxecmd",
            "pecmd",
            "recmd",
            "lecmd",
            "jlecmd",
            "mftecmd",
            "amcacheparser",
            "appcompatcacheparser",
            "shimcacheparser",
            "sbecmd",
            "powershell",
        )
    )


def detect_evidence_type(path: Path, extracted_files: list[str] | None = None) -> EvidenceType:
    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    extracted_files = extracted_files or []
    lower_files = [item.lower() for item in extracted_files]
    if suffix == ".zip" and any(hint.lower() in file for hint in VELOCIRAPTOR_HINTS for file in lower_files):
        return EvidenceType.velociraptor_zip
    if suffix in {".7z", ".zip"} and any(token.lower() in lower_name for token in ["kape", "parseado", "ez", "zimmerman"]):
        return EvidenceType.kape_archive
    if path.is_dir():
        return EvidenceType.parsed_folder
    if suffix == ".evtx":
        return EvidenceType.evtx
    if suffix in {".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff4"}:
        return EvidenceType.memory_dump
    if suffix in {".pcap", ".pcapng"}:
        return EvidenceType.pcap
    if suffix in {".yar", ".yara"}:
        return EvidenceType.yara_rules
    if suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
            if isinstance(data, dict) and {"title", "logsource", "detection"} & set(data.keys()):
                return EvidenceType.sigma_rules
        except Exception:  # noqa: BLE001
            pass
    if any(token in lower_name for token in ["linux", "triage-linux"]):
        return EvidenceType.linux_triage
    if any(token in lower_name for token in ["macos", "osx", "mac_triage"]):
        return EvidenceType.macos_triage
    if suffix == ".csv":
        return EvidenceType.csv
    if suffix == ".json":
        return EvidenceType.json
    if suffix == ".jsonl":
        return EvidenceType.jsonl
    if suffix == ".txt":
        return EvidenceType.txt
    if any(hint.lower() in file for hint in VELOCIRAPTOR_HINTS for file in lower_files):
        return EvidenceType.velociraptor_zip
    return EvidenceType.unknown


def detect_host_from_name(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"([A-Za-z0-9][A-Za-z0-9._-]{1,63})", value)
    if not match:
        return None
    candidate = match.group(1)
    if candidate.lower() in {"csv", "json", "txt", "zip", "7z"}:
        return None
    return candidate.upper()


def classify_artifact(path: Path, headers: list[str] | None = None) -> dict:
    name = path.name
    lower_name = name.lower()
    header_blob = " ".join((headers or [])).lower()
    header_set = {str(header).strip().lower() for header in (headers or []) if header}
    if lower_name == "$mft":
        return {
            "artifact_type": "mft",
            "profile": "filesystem",
            "parser": "mft_raw",
            "reason": "Detected raw $MFT file; inventory preserved even if not parsed directly.",
        }
    if lower_name in {"$usnjrnl", "$logfile", "$i30"} or lower_name.endswith("zone.identifier"):
        return {
            "artifact_type": "ntfs",
            "profile": "filesystem",
            "parser": "ntfs_generic_raw",
            "reason": "Detected raw NTFS deep artifact; inventory preserved even if not parsed directly.",
        }
    if lower_name in {"thumbs.db", "activitiescache.db", "windows.edb", "eventtranscript.db", "wpndatabase.db"} or lower_name.startswith("thumbcache_") or "oalerts.evtx" in lower_name:
        return {
            "artifact_type": "windows_ui",
            "profile": "user_activity",
            "parser": "windows_ui_generic_raw",
            "reason": "Detected raw Windows UI/local DB artifact; inventory preserved even if not parsed directly.",
        }
    if lower_name in {"readme.txt", "readme.md", "readme"}:
        return {
            "artifact_type": "document",
            "profile": "collection_metadata",
            "parser": "unsupported_text",
            "reason": "Detected collection README/supporting text file; preserved but not parsed as forensic event content.",
        }
    if lower_name in {"login data", "logins.json", "cookies", "cookies.sqlite"}:
        return {
            "artifact_type": "browser",
            "profile": "browser_usage",
            "parser": "unsupported_sensitive_artifact",
            "reason": "Detected sensitive browser credential/cookie store; values are intentionally not parsed or indexed.",
        }
    if _is_tool_console_log(path):
        return {
            "artifact_type": "tool_log",
            "profile": "collection_metadata",
            "parser": "not_implemented",
            "reason": "Detected EZ Tools console log; preserved but not indexed as forensic event content.",
        }
    if looks_like_ntfs_artifact(path, headers):
        parser = "ntfs_generic_raw"
        if {"zoneid", "hosturl", "referrerurl"} & header_set:
            parser = "ntfs_ads_zone_identifier"
        elif {"shadowid", "snapshottime"} & header_set:
            parser = "ntfs_shadowcopy"
        elif "reason" in header_set and ("usn" in header_set or "filereference" in header_set):
            parser = "ntfs_usnjrnl"
        elif "oldname" in header_set or "newname" in header_set or "$logfile" in lower_name:
            parser = "ntfs_logfile"
        elif ({"inuse", "isdeleted"} & header_set) and {"entrynumber", "sequencenumber"} <= header_set:
            parser = "ntfs_i30"
        return {
            "artifact_type": "ntfs",
            "profile": "filesystem",
            "parser": parser,
        }
    if looks_like_windows_ui_artifact(path, headers):
        parser = "windows_ui_generic_raw"
        if {"thumbnailcacheid", "cacheentryhash", "thumbnailpath"} & header_set:
            parser = "windows_thumbcache"
        elif lower_name == "thumbs.db":
            parser = "windows_thumbsdb"
        elif {"notificationid", "toast", "title", "bodypreview"} & header_set or "notification" in lower_name or "wpndatabase" in lower_name:
            parser = "windows_notifications"
        elif {"activityid", "displaytext", "activationuri"} & header_set or "activitiescache" in lower_name:
            parser = "windows_activitiescache"
        elif {"indexedpath", "contenttype"} & header_set:
            parser = "windows_search_index"
        elif ("eventtext" in header_set or "provider" in header_set) and "eventtranscript" in lower_name:
            parser = "windows_eventtranscript"
        elif "alerttext" in header_set or "oalerts" in lower_name:
            parser = "office_oalerts_evtx"
        elif "cacheid" in header_set or "officefilecache" in lower_name or "office_filecache" in lower_name:
            parser = "office_filecache"
        elif "backstage" in lower_name or ("documentpath" in header_set and "officeapp" in header_set):
            parser = "office_backstage"
        return {
            "artifact_type": "windows_ui",
            "profile": "user_activity",
            "parser": parser,
        }
    eztools_match = detect_eztool_output(path, headers)
    if eztools_match:
        tool = eztools_match["tool"]
        if tool == "evtxecmd":
            return {"artifact_type": "evtx", "profile": "account_usage", "parser": "zimmerman"}
        if tool == "pecmd":
            return {"artifact_type": "prefetch", "profile": "program_execution", "parser": "zimmerman"}
        if tool == "recmd":
            return {"artifact_type": "registry", "profile": "registry", "parser": "zimmerman"}
        if tool == "lecmd":
            return {"artifact_type": "lnk", "profile": "file_folder_opening", "parser": "zimmerman"}
        if tool == "jlecmd":
            return {"artifact_type": "jumplist", "profile": "file_folder_opening", "parser": "zimmerman"}
        if tool == "mftecmd":
            if eztools_match.get("artifact_type") == "usn":
                if path.suffix.lower() == ".jsonl":
                    return {"artifact_type": "usn", "profile": "filesystem", "parser": "usn_jsonl"}
                if path.suffix.lower() == ".json":
                    return {"artifact_type": "usn", "profile": "filesystem", "parser": "usn_json"}
                if path.suffix.lower() == ".csv" and "mftecmd" not in lower_name and "usnjrnl" not in lower_name:
                    return {"artifact_type": "usn", "profile": "filesystem", "parser": "usn_csv"}
                return {"artifact_type": "usn", "profile": "filesystem", "parser": "zimmerman"}
            if path.suffix.lower() == ".jsonl":
                return {"artifact_type": "mft", "profile": "filesystem", "parser": "mft_jsonl"}
            if path.suffix.lower() == ".json":
                return {"artifact_type": "mft", "profile": "filesystem", "parser": "mft_json"}
            if path.suffix.lower() == ".csv" and "mftecmd" not in lower_name:
                return {"artifact_type": "mft", "profile": "filesystem", "parser": "mft_csv"}
            return {"artifact_type": "mft", "profile": "filesystem", "parser": "zimmerman"}
    if (
        {"entrynumber", "sequencenumber"} <= header_set
        and (
            {"fullpath", "path", "filename"} & header_set
            or {"created0x10", "modified0x10", "lastrecordchange0x10", "si_created", "si_changed"} & header_set
            or {"inuse", "isdeleted", "hasads", "adsname"} & header_set
        )
    ):
        parser = (
            "mft_jsonl" if path.suffix.lower() == ".jsonl"
            else "mft_json" if path.suffix.lower() == ".json"
            else "mft_csv" if path.suffix.lower() == ".csv"
            else "mft_raw"
        )
        return {
            "artifact_type": "mft",
            "profile": "filesystem",
            "parser": parser,
        }
    if lower_name == "srudb.dat":
        return {
            "artifact_type": "srum",
            "profile": "network_activity",
            "parser": "srum_db",
            "srum_artifact_type": "srum_database",
        }
    if looks_like_email_artifact(path, headers):
        normalized_path = str(path).replace("/", "\\").lower()
        suffix = path.suffix.lower()
        parser = (
            "email_eml" if suffix == ".eml"
            else "email_mbox" if suffix == ".mbox"
            else "email_pst_inventory" if suffix == ".pst"
            else "email_ost_inventory" if suffix == ".ost"
            else "email_windows_mail_inventory" if path.name.lower() == "store.vol" and "comms" in normalized_path
            else "email_outlook_temp_attachment" if "content.outlook" in normalized_path
            else "email_mbox" if "thunderbird\\profiles\\" in normalized_path and suffix not in {".msf", ".sqlite"}
            else "email_generic_raw"
        )
        email_artifact_type = (
            "email_message" if parser in {"email_eml", "email_mbox"}
            else "email_pst_inventory" if parser == "email_pst_inventory"
            else "email_ost_inventory" if parser == "email_ost_inventory"
            else "email_windows_mail_inventory" if parser == "email_windows_mail_inventory"
            else "email_outlook_temp_attachment" if parser == "email_outlook_temp_attachment"
            else "email_generic_raw"
        )
        return {
            "artifact_type": "email",
            "profile": "email",
            "parser": parser,
            "email_artifact_type": email_artifact_type,
        }
    if any(
        token in header_blob
        for token in [
            "bytessent",
            "bytesreceived",
            "sendbytes",
            "receivebytes",
            "foregroundbytessent",
            "backgroundbytesreceived",
            "networkprofile",
            "interfaceprofile",
            "interfaceguid",
            "connectedtime",
            "duration",
            "appid",
            "appname",
            "applicationresourceusage",
            "energyusage",
        ]
    ):
        return {"artifact_type": "srum", "profile": "network_activity", "parser": _structured_srum_parser(path)}
    dns_header_tokens = {
        "queryname",
        "recordname",
        "recordtype",
        "ttl",
        "dnsserver",
        "querystatus",
        "processname",
        "eventid",
        "address",
        "cname",
        "name",
        "data",
        "status",
        "server",
    }
    dns_header_hint = any(token in header_blob for token in dns_header_tokens)
    explicit_dns_header_pattern = (
        ("queryname" in header_blob and "recordtype" in header_blob)
        or ("name" in header_blob and "recordtype" in header_blob and any(token in header_blob for token in ["data", "address", "status", "ttl"]))
    )
    if (
        (any(token in lower_name for token in ["dns", "displaydns", "dns-client", "dns_client"]) and path.suffix.lower() in {".json", ".jsonl", ".csv", ".txt"})
        or (path.suffix.lower() in {".json", ".jsonl", ".csv"} and explicit_dns_header_pattern)
    ):
        parser = (
            "dns_evtx" if any(token in lower_name for token in ["dns-client", "dns_client"]) and path.suffix.lower() in {".json", ".jsonl"}
            else "dns_jsonl" if path.suffix.lower() == ".jsonl"
            else "dns_json" if path.suffix.lower() == ".json"
            else "dns_csv" if path.suffix.lower() == ".csv"
            else "dns_raw"
        )
        network_artifact_type = (
            "dns_evtx" if parser == "dns_evtx"
            else "dns_cache_output" if any(token in lower_name for token in ["displaydns", "dnscache"]) or dns_header_hint
            else "network_generic"
        )
        return {
            "artifact_type": "dns",
            "profile": "network_activity",
            "parser": parser,
            "network_artifact_type": network_artifact_type,
        }
    if looks_like_autoruns_artifact(path, headers):
        lower_name = name.lower()
        parser = (
            "autoruns_xml" if path.suffix.lower() == ".xml"
            else "autoruns_tsv" if path.suffix.lower() == ".tsv"
            else "autoruns_jsonl" if path.suffix.lower() == ".jsonl"
            else "autoruns_json" if path.suffix.lower() == ".json"
            else "autoruns_csv"
        )
        autoruns_subtype = (
            "wmi_persistence" if "wmi" in lower_name
            else "scheduled_task" if "task" in lower_name
            else "startup_folder" if "startup" in lower_name
            else "autoruns_entry"
        )
        return {
            "artifact_type": "autoruns",
            "profile": "persistence",
            "parser": parser,
            "autoruns_artifact_type": autoruns_subtype,
        }
    if looks_like_scheduled_task_artifact(path, headers):
        return {
            "artifact_type": "scheduled_task",
            "profile": "persistence",
            "parser": "scheduled_task_xml" if path.suffix.lower() == ".xml" or path.suffix == "" else "csv",
        }
    if looks_like_powershell_artifact(path, headers):
        lower_name = name.lower()
        lower_headers = " ".join(headers or []).lower()
        parser = (
            "powershell_json" if path.suffix.lower() == ".json"
            else "powershell_jsonl" if path.suffix.lower() == ".jsonl"
            else "powershell_csv" if path.suffix.lower() == ".csv"
            else "powershell_script" if path.suffix.lower() in {".ps1", ".psm1", ".psd1"}
            else "powershell_history" if "consolehost_history" in lower_name or "psreadline" in lower_name
            else "powershell_transcript" if "transcript" in lower_name or any(token in lower_headers for token in ["host application", "runas user", "command start time"])
            else "powershell_json"
        )
        artifact_subtype = (
            "powershell_script" if parser == "powershell_script"
            else "psreadline_history" if parser == "powershell_history"
            else "powershell_transcript" if parser == "powershell_transcript"
            else "powershell_command" if parser in {"powershell_csv", "powershell_json", "powershell_jsonl"}
            else "powershell_generic"
        )
        return {
            "artifact_type": "powershell",
            "profile": "powershell",
            "parser": parser,
            "powershell_artifact_type": artifact_subtype,
        }
    if looks_like_browser_artifact(path, headers):
        return classify_browser_artifact(path, headers)
    if name.lower() in {"qmgr0.dat", "qmgr1.dat", "qmgr.db"}:
        return {
            "artifact_type": "bits",
            "profile": "network_activity",
            "parser": "bits_qmgr",
            "bits_artifact_type": "bits_qmgr_db" if name.lower() == "qmgr.db" else "bits_qmgr_dat",
        }
    if looks_like_bits_artifact(path, headers):
        lower_name = name.lower()
        parser = (
            "bits_jsonl" if path.suffix.lower() == ".jsonl"
            else "bits_json" if path.suffix.lower() == ".json"
            else "bits_raw" if "bitsadmin" in lower_name and path.suffix.lower() == ".txt"
            else "bits_csv"
        )
        bits_subtype = (
            "bits_transfer" if path.suffix.lower() in {".csv", ".json", ".jsonl", ".txt"}
            else "bits_job"
        )
        return {
            "artifact_type": "bits",
            "profile": "network_activity",
            "parser": parser,
            "bits_artifact_type": bits_subtype,
        }
    if looks_like_defender_artifact(path, headers):
        lower_name = name.lower()
        suffix = path.suffix.lower()
        if "detectionhistory" in lower_name or "detection_history" in lower_name:
            parser = "defender_detection_history"
        elif "mplog" in lower_name:
            parser = "defender_mplog"
        elif "quarantine" in lower_name:
            parser = "defender_quarantine_metadata"
        elif suffix == ".json":
            parser = "defender_json"
        elif suffix == ".jsonl":
            parser = "defender_jsonl"
        elif suffix in {".csv", ".tsv", ".txt"}:
            parser = "defender_csv"
        elif suffix == ".log":
            parser = "defender_mplog"
        else:
            parser = "defender_detection_history"
        return {
            "artifact_type": "defender",
            "profile": "detection",
            "parser": parser,
            "defender_artifact_type": (
                "defender_detection_history" if ("detectionhistory" in lower_name or "detection_history" in lower_name)
                else "defender_mplog" if "mplog" in lower_name
                else "defender_quarantine_metadata" if "quarantine" in lower_name
                else "defender_jsonl" if suffix == ".jsonl"
                else "defender_json" if suffix == ".json"
                else "defender_csv" if suffix in {".csv", ".tsv", ".txt"}
                else "defender_generic"
            ),
        }
    if looks_like_recycle_bin_artifact(path, headers):
        lower_name = name.lower()
        suffix = path.suffix.lower()
        parser = (
            "raw_i_file" if lower_name.startswith("$i")
            else "rbcmd" if suffix == ".csv" or "rbcmd" in lower_name
            else "jsonl" if suffix == ".jsonl"
            else "json" if suffix == ".json"
            else "csv" if suffix == ".csv"
            else "raw_i_file" if "$i" in lower_name
            else "generic"
        )
        recycle_subtype = (
            "recycle_i_file" if parser == "raw_i_file"
            else "recycle_bin_jsonl" if parser == "jsonl"
            else "recycle_bin_json" if parser == "json"
            else "recycle_bin_csv" if parser in {"rbcmd", "csv"}
            else "recycle_generic"
        )
        return {
            "artifact_type": "recycle_bin",
            "profile": "filesystem",
            "parser": parser,
            "recycle_artifact_type": recycle_subtype,
        }
    if looks_like_usb_artifact(path, headers):
        lower_name = name.lower()
        parser = (
            "usb_setupapi" if lower_name in {"setupapi.dev.log", "setupapi.setup.log"} or path.suffix.lower() == ".log"
            else "usb_evtx" if path.suffix.lower() in {".json", ".jsonl"} and any(token in lower_name for token in ["userpnp", "kernel-pnp", "driverframeworks"])
            else "usb_mounteddevices" if "mounteddevices" in lower_name
            else "usb_mountpoints2" if "mountpoints2" in lower_name
            else "usb_registry" if any(token in lower_name for token in ["usbstor", "portabledevices", "deviceclasses", "wpd"])
            else "usb_jsonl" if path.suffix.lower() == ".jsonl"
            else "usb_json" if path.suffix.lower() == ".json"
            else "usb_raw" if path.suffix.lower() == ".txt"
            else "usb_csv"
        )
        usb_subtype = (
            "usb_evtx" if parser == "usb_evtx"
            else "usb_setupapi" if parser == "usb_setupapi"
            else "mounted_device" if "mounteddevices" in lower_name
            else "mountpoints2" if "mountpoints2" in lower_name
            else "portable_device" if "portabledevices" in lower_name
            else "usbstor_device" if "usbstor" in lower_name
            else "usb_registry_entry"
        )
        return {
            "artifact_type": "usb",
            "profile": "device_activity",
            "parser": parser,
            "usb_artifact_type": usb_subtype,
        }
    if looks_like_cloud_sync_artifact(path, headers):
        lower_name = name.lower()
        parser = (
            "cloud_onedrive_jsonl" if path.suffix.lower() == ".jsonl"
            else "cloud_onedrive_json" if path.suffix.lower() == ".json"
            else "cloud_raw" if path.suffix.lower() in {".log", ".txt", ".ini"}
            else "cloud_onedrive_csv"
        )
        source_tool = (
            "onedrive" if "onedrive" in lower_name
            else "google_drive" if "drivefs" in lower_name or "google" in lower_name
            else "dropbox" if "dropbox" in lower_name
            else "mega" if "mega" in lower_name
            else "icloud" if "icloud" in lower_name
            else "box" if "box" in lower_name
            else "generic_cloud"
        )
        return {
            "artifact_type": "cloud",
            "profile": "cloud",
            "parser": parser,
            "cloud_artifact_type": "cloud_client_log" if parser == "cloud_raw" else "cloud_client_config" if "config" in lower_name or "settings" in lower_name or lower_name.endswith(".ini") else "onedrive_item",
            "source_tool": source_tool,
        }
    if looks_like_network_artifact(path, headers):
        lower_name = name.lower()
        header_blob = " ".join((headers or [])).lower()
        wlan_header_hint = any(
            token in header_blob
            for token in ["ssid", "bssid", "authentication", "encryption", "keyprotected", "keymaterialpresent", "interfaceguid", "signalquality", "profilename"]
        )
        dns_header_hint = any(
            token in header_blob
            for token in ["queryname", "recordname", "recordtype", "ttl", "dnsserver", "querystatus", "processname", "eventid", "address", "cname"]
        )
        parser = (
            "wlan_profile_xml" if path.suffix.lower() == ".xml"
            else "hosts_file" if lower_name == "hosts"
            else "wlan_jsonl" if ("wlan" in lower_name or wlan_header_hint) and path.suffix.lower() == ".jsonl"
            else "dns_jsonl" if ("dns" in lower_name or dns_header_hint) and path.suffix.lower() == ".jsonl"
            else "wlan_json" if ("wlan" in lower_name or wlan_header_hint) and path.suffix.lower() == ".json"
            else "dns_json" if ("dns" in lower_name or dns_header_hint) and path.suffix.lower() == ".json"
            else "network_json" if path.suffix.lower() == ".json"
            else "wlan_csv" if (any(token in lower_name for token in ["wlan", "wifi"]) or wlan_header_hint) and path.suffix.lower() == ".csv"
            else "dns_csv" if "dns" in lower_name and path.suffix.lower() == ".csv"
            else "ipconfig_txt" if "ipconfig" in lower_name
            else "dns_raw" if "displaydns" in lower_name
            else "wlan_raw" if "netsh" in lower_name or "wlan" in lower_name
            else "network_csv" if path.suffix.lower() == ".csv"
            else "network_txt"
        )
        network_artifact_type = (
            "wlan_profile_xml" if parser == "wlan_profile_xml"
            else "wlan_evtx" if "wlan-autoconfig" in lower_name or "wlan_autoconfig" in lower_name
            else "dns_evtx" if "dns-client" in lower_name or "dns_client" in lower_name
            else "hosts_file" if parser == "hosts_file"
            else "dns_cache_output" if "dnscache" in lower_name or "displaydns" in lower_name
            else "dns_config_output" if any(token in lower_name for token in ["dnsclientserveraddress", "dnsserver", "dns_config"])
            else "ipconfig_output" if "ipconfig" in lower_name
            else "netsh_wlan_output" if "netsh" in lower_name or "wlan" in lower_name
            else "netadapter_output" if "netadapter" in lower_name
            else "netipconfiguration_output" if "netipconfiguration" in lower_name
            else "route_table_output" if "route" in lower_name
            else "netstat_output" if "netstat" in lower_name
            else "arp_output" if "arp" in lower_name
            else "networklist_registry" if "networklist" in lower_name
            else "tcpip_interfaces_registry" if "tcpip" in lower_name or "interfaces" in lower_name
            else "network_generic"
        )
        artifact_family = (
            "wlan" if network_artifact_type in {"wlan_profile_xml", "wlan_evtx", "netsh_wlan_output"} or parser in {"wlan_profile_xml", "wlan_evtx", "wlan_csv", "wlan_json", "wlan_jsonl", "wlan_raw"}
            else "dns" if network_artifact_type in {"dns_cache_output", "dns_evtx"} or parser in {"dns_csv", "dns_json", "dns_jsonl", "dns_evtx", "dns_raw"}
            else "network"
        )
        return {
            "artifact_type": artifact_family,
            "profile": "network_activity",
            "parser": parser,
            "network_artifact_type": network_artifact_type,
        }
    if looks_like_wmi_artifact(path, headers):
        lower_name = name.lower()
        parser = "wmi_jsonl" if path.suffix.lower() == ".jsonl" else "wmi_json" if path.suffix.lower() == ".json" else "autoruns" if "autoruns" in lower_name else "wmi_csv"
        wmi_subtype = (
            "wmi_filter_to_consumer_binding" if "filtertoconsumerbinding" in lower_name
            else "wmi_command_line_consumer" if "commandlineeventconsumer" in lower_name
            else "wmi_active_script_consumer" if "activescripteventconsumer" in lower_name
            else "wmi_event_filter" if "eventfilter" in lower_name
            else "wmi_activity_event" if "wmi-activity" in lower_name
            else "wmi_generic"
        )
        return {
            "artifact_type": "wmi",
            "profile": "persistence",
            "parser": parser,
            "wmi_artifact_type": wmi_subtype,
        }
    if path.suffix.lower() == ".automaticdestinations-ms":
        return {
            "artifact_type": "jumplist",
            "profile": "file_folder_opening",
            "parser": "raw_automatic_destinations",
            "jumplist_artifact_type": "jumplist_automatic_destinations",
        }
    if path.suffix.lower() == ".customdestinations-ms":
        return {
            "artifact_type": "jumplist",
            "profile": "file_folder_opening",
            "parser": "raw_custom_destinations",
            "jumplist_artifact_type": "jumplist_custom_destinations",
        }
    if path.suffix.lower() == ".evtx":
        return {
            "artifact_type": "windows_event",
            "profile": "account_usage",
            "parser": "evtx_raw",
        }
    if path.suffix.lower() == ".lnk":
        return {
            "artifact_type": "lnk",
            "profile": "file_folder_opening",
            "parser": "lnk_raw",
        }
    if path.suffix.lower() == ".pf":
        return {
            "artifact_type": "prefetch",
            "profile": "program_execution",
            "parser": "prefetch_raw",
        }
    if path.name.lower() == "amcache.hve":
        return {
            "artifact_type": "amcache",
            "profile": "execution_artifact",
            "parser": "amcache_raw",
        }
    if path.name.lower() in {"ntuser.dat", "usrclass.dat"}:
        return {
            "artifact_type": "user_activity",
            "profile": "registry",
            "parser": "user_activity_registry_raw",
        }
    if looks_like_jumplist_artifact(path, headers):
        lower_name = name.lower()
        jumplist_subtype = (
            "automatic_destinations" if "automaticdestinations" in lower_name
            else "custom_destinations" if "customdestinations" in lower_name
            else "jumplist_entry"
        )
        return {
            "artifact_type": "jumplist",
            "profile": "file_folder_opening",
            "parser": "jlecmd" if "jlecmd" in lower_name else "csv",
            "jumplist_artifact_type": jumplist_subtype,
        }
    if looks_like_shellbags_artifact(path, headers):
        lower_name = name.lower()
        parser = "sbecmd" if "sbecmd" in lower_name or path.suffix.lower() == ".csv" else "csv"
        shellbag_subtype = "shellbag_generic"
        if any(token in lower_name for token in ["network", "unc"]):
            shellbag_subtype = "shellbag_network_folder"
        elif any(token in lower_name for token in ["usb", "removable"]):
            shellbag_subtype = "shellbag_usb_folder"
        return {
            "artifact_type": "shellbags",
            "profile": "file_folder_opening",
            "parser": parser,
            "shellbag_artifact_type": shellbag_subtype,
        }
    for token, (artifact_type, profile, parser) in VELOCI_ARTIFACT_MAP.items():
        if token.lower() in name.lower():
            return {"artifact_type": artifact_type, "profile": profile, "parser": parser}
    for token, (artifact_type, profile, parser) in KAPE_NAME_MAP.items():
        if token.lower() in name.lower():
            return {"artifact_type": artifact_type, "profile": profile, "parser": parser}
    if "eventid" in header_blob:
        return {"artifact_type": "evtx", "profile": "account_usage", "parser": "generic_csv"}
    if "destinationip" in header_blob or "remoteaddress" in header_blob:
        return {"artifact_type": "network", "profile": "network_activity", "parser": "generic_csv"}
    if "processname" in header_blob or "imagename" in header_blob:
        return {"artifact_type": "process", "profile": "program_execution", "parser": "generic_csv"}
    if ("programname" in header_blob or "publisher" in header_blob) and any(token in header_blob for token in ["sha1", "sha256", "compiletime", "installdate", "longpathhash"]):
        return {"artifact_type": "amcache", "profile": "execution_artifact", "parser": "generic_csv"}
    if ("shimcache" in header_blob or "appcompatcache" in header_blob or "recentfilecache" in header_blob) or ("path" in header_blob and any(token in header_blob for token in ["lastmodifiedtime", "executed", "cacheentryposition", "shimflags"])):
        artifact_type = "appcompat" if "recentfilecache" in header_blob else "shimcache"
        return {"artifact_type": artifact_type, "profile": "execution_artifact", "parser": "generic_csv"}
    if any(token in header_blob for token in ["bytessent", "bytesreceived", "sendbytes", "receivebytes", "foregroundbytessent", "backgroundbytesreceived", "networkprofile", "interfaceprofile", "appid", "appname", "applicationresourceusage", "energyusage"]):
        return {"artifact_type": "srum", "profile": "network_activity", "parser": _structured_srum_parser(path)}
    scheduled_task_header_hits = sum(
        1
        for token in ["taskname", "taskpath", "author", "description", "uri", "command", "arguments", "workingdirectory", "enabled", "principal", "userid", "runlevel", "triggers", "actions", "registrationinfo"]
        if token in header_blob
    )
    if scheduled_task_header_hits >= 3:
        return {"artifact_type": "scheduled_task", "profile": "persistence", "parser": "csv"}
    if any(token in header_blob for token in ["jobid", "jobguid", "displayname", "ownersid", "notifycmdline", "notifycommandline", "remoteurl", "localfile", "filestransferred", "bytestransferred"]):
        return {"artifact_type": "bits", "profile": "network_activity", "parser": "bits_csv", "bits_artifact_type": "bits_job"}
    if any(token in header_blob for token in ["namespace", "classname", "commandlinetemplate", "scripttext", "creatorsid", "__path", "__relpath", "filtername", "consumername", "querylanguage", "eventnamespace"]):
        return {"artifact_type": "wmi", "profile": "persistence", "parser": "wmi_csv", "wmi_artifact_type": "wmi_generic"}
    if any(token in header_blob for token in ["threatname", "threatid", "detectiontime", "initialdetectiontime", "resource", "resources", "severity", "remediation", "detectionsource", "productname"]):
        return {"artifact_type": "defender", "profile": "detection", "parser": "defender_csv", "defender_artifact_type": "defender_csv"}
    if any(token in header_blob for token in ["command", "scriptblocktext", "commandstarttime", "hostapplication", "username", "runasuser", "psversion"]):
        return {"artifact_type": "powershell", "profile": "powershell", "parser": "csv", "powershell_artifact_type": "powershell_command"}
    if any(token in header_blob for token in ["sourcefile", "appid", "appiddescription", "entrynumber", "targetpath", "localpath", "targetaccessed", "lastaccessed", "drivetype", "volumeserialnumber", "machineid"]):
        return {"artifact_type": "jumplist", "profile": "file_folder_opening", "parser": "csv", "jumplist_artifact_type": "jumplist_entry"}
    if any(token in header_blob for token in ["bagpath", "absolutepath", "shellitempath", "folderpath", "shelltype", "mruposition", "nodeslot", "lastinteracted", "lastwritetime", "extensionblock", "hivepath"]):
        return {"artifact_type": "shellbags", "profile": "file_folder_opening", "parser": "csv", "shellbag_artifact_type": "shellbag_generic"}
    if path.suffix.lower() == ".json":
        return {"artifact_type": "generic_json", "profile": "unknown", "parser": "generic_json"}
    return {"artifact_type": "generic_csv", "profile": "unknown", "parser": "generic_csv"}
