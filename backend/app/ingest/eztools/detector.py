from pathlib import Path

from app.ingest.cloud_sync.helpers import canonicalize_header as canonicalize_cloud_header
from app.ingest.cloud_sync.helpers import looks_like_cloud_sync_artifact


EZ_NAME_HINTS = {
    "evtxecmd": "evtxecmd",
    "pecmd": "pecmd",
    "recmd": "recmd",
    "jlecmd": "jlecmd",
    "lecmd": "lecmd",
    "mftecmd": "mftecmd",
    "amcacheparser": "amcacheparser",
    "appcompatcacheparser": "appcompatcacheparser",
    "shimcacheparser": "shimcacheparser",
    "srumecmd": "srumecmd",
    "scheduledtasks": "scheduledtasks",
    "taskscheduler": "scheduledtasks",
    "powershell": "powershell",
    "scriptblock": "powershell",
    "sbecmd": "sbecmd",
    "rbcmd": "rbcmd",
    "recyclebin": "rbcmd",
    "recycle_bin": "rbcmd",
}


def detect_eztool_output(path: Path, headers: list[str] | None = None) -> dict | None:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    header_set = {header.strip().lower() for header in (headers or []) if header}
    canonical_headers = {canonicalize_cloud_header(header) for header in (headers or []) if header}
    if looks_like_cloud_sync_artifact(path, headers):
        return None
    if (
        suffix in {".csv", ".json", ".jsonl", ".txt", ".ini", ".log"}
        and (
            any(token in lower_name for token in ["onedrive", "cloudsync", "googledrive", "dropbox", "drivefs", "clientpolicy", "syncroot"])
            or len(
                canonical_headers
                & {
                    "provider",
                    "account",
                    "accountemail",
                    "syncroot",
                    "localpath",
                    "remotepath",
                    "cloudpath",
                    "lastsync",
                    "lastupload",
                    "lastdownload",
                }
            )
            >= 4
        )
    ):
        return None
    if (
        suffix in {".csv", ".json", ".jsonl", ".txt"}
        and (
            any(token in lower_name for token in ["bits", "qmgr", "bitsadmin"])
            or {"jobid", "jobguid", "remoteurl", "localpath"} <= header_set
            or ({"artifacttype", "jobguid", "remoteurl"} <= header_set and suffix == ".jsonl")
        )
    ):
        return None
    for token, tool in EZ_NAME_HINTS.items():
        if token in lower_name:
            if tool in {"sbecmd", "rbcmd", "scheduledtasks"} and suffix != ".csv":
                continue
            return {"tool": tool, "artifact_type": tool.replace("ecmd", "").replace("cmd", ""), "confidence": "name"}
    if any(token in lower_name for token in ["networkusage", "applicationresourceusage", "appresource", "energyusage", "networkconnectivity"]):
        return {"tool": "srumecmd", "artifact_type": "srum", "confidence": "name"}
    if any(token in lower_name for token in ["scheduledtasks", "scheduledtask", "taskscheduler"]):
        return {"tool": "scheduledtasks", "artifact_type": "scheduled_task", "confidence": "name"}
    if suffix == ".csv" and any(token in lower_name for token in ["jlecmd", "jumplist", "jumplists", "automaticdestinations", "customdestinations", "destinations"]):
        return {"tool": "jlecmd", "artifact_type": "jumplist", "confidence": "name"}
    if any(token in lower_name for token in ["consolehost_history", "psreadline", "powershell_transcript", "windowspowershell_transcript", "scriptblock", "powershell"]):
        return {"tool": "powershell", "artifact_type": "powershell", "confidence": "name"}
    if suffix == ".csv" and any(token in lower_name for token in ["rbcmd", "recyclebin", "recycle_bin", "recycle bin"]):
        return {"tool": "rbcmd", "artifact_type": "recycle_bin", "confidence": "name"}
    if {"eventid", "provider", "channel"} & header_set and {"message", "mapdescription"} & header_set:
        return {"tool": "evtxecmd", "artifact_type": "evtx", "confidence": "headers"}
    if {"reason", "usn"} & header_set and {"timestamp", "updatetimestamp", "filepath", "fullpath", "path"} & header_set:
        return {"tool": "mftecmd", "artifact_type": "usn", "confidence": "headers"}
    if {"entrynumber", "sequencenumber", "parententrynumber"} <= header_set:
        return {"tool": "mftecmd", "artifact_type": "mft", "confidence": "headers"}
    if (
        {"entrynumber", "sequencenumber"} <= header_set
        and (
            {"fullpath", "path", "filename"} & header_set
            or {"created0x10", "modified0x10", "lastrecordchange0x10", "si_created", "si_changed"} & header_set
            or {"inuse", "isdeleted", "hasads", "adsname"} & header_set
        )
    ):
        return {"tool": "mftecmd", "artifact_type": "mft", "confidence": "headers"}
    if {"executablename", "runcount"} <= header_set or {"applicationname", "runcount"} <= header_set or {"sourcefilename", "runcount", "lastrun"} <= header_set:
        return {"tool": "pecmd", "artifact_type": "prefetch", "confidence": "headers"}
    if {"appid", "sourcefile"} <= header_set and ({"targetpath", "path"} & header_set):
        return {"tool": "jlecmd", "artifact_type": "jumplist", "confidence": "headers"}
    if {"appiddescription", "interactioncount"} <= header_set and ({"localpath", "path", "targetpath"} & header_set):
        return {"tool": "jlecmd", "artifact_type": "jumplist", "confidence": "headers"}
    if {"targetpath", "arguments"} <= header_set or {"sourcefile", "localpath", "machineid"} <= header_set:
        return {"tool": "lecmd", "artifact_type": "lnk", "confidence": "headers"}
    if {"keypath", "valuename"} <= header_set and ({"valuedata", "data", "hive", "lastwritetime"} & header_set):
        return {"tool": "recmd", "artifact_type": "registry", "confidence": "headers"}
    if {"programname", "publisher"} & header_set and ({"sha1", "sha256", "compiletime", "installdate", "lowercaselongpath", "longpathhash"} & header_set):
        return {"tool": "amcacheparser", "artifact_type": "amcache", "confidence": "headers"}
    if {"path", "lastmodifiedtime", "entrynumber"} & header_set and ({"executed", "shimflags", "insertflags", "controlset", "cacheentryposition"} & header_set):
        return {"tool": "appcompatcacheparser", "artifact_type": "shimcache", "confidence": "headers"}
    if {"path", "lastmodifiedtime"} & header_set and {"appcompatcache", "shimcache", "recentfilecache"} & header_set:
        return {"tool": "shimcacheparser", "artifact_type": "shimcache", "confidence": "headers"}
    if {"path", "name"} & header_set and {"recentfilecache", "datasource", "appcompatflags"} & header_set:
        return {"tool": "shimcacheparser", "artifact_type": "appcompat", "confidence": "headers"}
    if {"appid", "appname", "application", "exepath", "path", "usersid", "sid"} & header_set and {"bytessent", "bytesreceived", "sendbytes", "receivebytes", "networkprofile", "interfaceprofile"} & header_set:
        return {"tool": "srumecmd", "artifact_type": "srum", "confidence": "headers"}
    if {"table", "timestamp", "starttime", "endtime", "appid", "application", "duration", "cycletime", "energyusage"} & header_set and {"usersid", "sid", "username"} & header_set:
        return {"tool": "srumecmd", "artifact_type": "srum", "confidence": "headers"}
    if {"taskname", "taskpath", "author", "command", "arguments", "enabled"} & header_set and {"triggers", "actions", "userid", "runlevel", "workingdirectory"} & header_set:
        return {"tool": "scheduledtasks", "artifact_type": "scheduled_task", "confidence": "headers"}
    if {"command", "scriptblocktext", "hostapplication", "username", "runasuser", "commandstarttime"} & header_set:
        return {"tool": "powershell", "artifact_type": "powershell", "confidence": "headers"}
    if {"deletedon", "deletiontime", "originalfilename", "originalpath", "filesize", "sid", "sourcefile"} & header_set:
        return {"tool": "rbcmd", "artifact_type": "recycle_bin", "confidence": "headers"}
    if {"sourcefile", "appid", "appiddescription", "entrynumber", "targetpath", "localpath", "targetaccessed", "lastaccessed", "drivetype", "volumeserialnumber", "machineid"} & header_set:
        return {"tool": "jlecmd", "artifact_type": "jumplist", "confidence": "headers"}
    if {"bagpath", "absolutepath", "path", "shellitempath", "folderpath", "shelltype", "slot", "nodeslot", "mruposition", "lastwritetime", "extensionblock", "sourcefile", "hivepath"} & header_set:
        return {"tool": "sbecmd", "artifact_type": "shellbags", "confidence": "headers"}
    return None
