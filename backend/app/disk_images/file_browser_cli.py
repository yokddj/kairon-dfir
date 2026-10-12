"""Sandboxed helper behind the disk file explorer.

Run as ``python -m app.disk_images.file_browser_cli`` with one JSON request on
stdin; it answers with one JSON document on stdout. The API never opens a
filesystem itself: TSK is C code reading attacker-controlled structures, so a
malformed image may crash or hang it, and doing that in a child process the
API kills on a timeout keeps the server up. Everything here is read-only.

Operations:
  list    -- one directory, by inode or path (root when neither is given)
  find    -- walk the tree for names matching a glob
  export  -- copy files (or whole directories) out by inode into output_dir

A deleted name is reported with how much of it survives, because that decides
whether its content can be trusted:
  deleted               -- the inode is free and was not reused: content may
                           still be there (NTFS usually; ext3/ext4 zero the
                           block pointers, so it is often gone)
  deleted_inode_reused  -- the inode now belongs to another, live object, so
                           its content is not this file's
  deleted_metadata_lost -- only the name is left
  deleted_journal       -- (ext3/ext4) gone from the directory, but an old
                           copy of the directory block in the journal still
                           holds it; see app.disk_images.ext_journal
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
from typing import Any

import pytsk3

from app.disk_images.ewf_img_info import EwfImgInfo
from app.disk_images.ext_journal import ExtJournal
from app.disk_images.volume_access import _PytskFileReader, _open_persisted_volume_fs_info, _volume_byte_reader


_CHUNK = 1024 * 1024
_UNSAFE_NAME = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')


# One request per process: the opened image and, lazily, its journal index.
_context: dict[str, Any] = {}


class BrowserError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _open_fs(request: dict[str, Any]) -> tuple[Any, pytsk3.FS_Info]:
    image = request["image"]
    segments = [Path(item) for item in image["segments"]]
    if image["format"] == "ewf":
        reader = EwfImgInfo(segments)
    else:
        reader = _PytskFileReader(segments[0])
    volume = request["volume"]
    spec = SimpleNamespace(
        offset_bytes=int(volume.get("offset_bytes") or 0),
        partition_index=int(volume.get("partition_index") or 0),
        metadata_json=volume.get("metadata") or {},
        warnings_json=volume.get("warnings") or [],
    )
    _context.update(reader=reader, spec=spec, request=request)
    try:
        return reader, _open_persisted_volume_fs_info(reader, spec)
    except Exception as exc:
        reader.close()
        raise BrowserError("volume_unreadable", f"The filesystem could not be opened: {exc}") from exc


def _flag(value: Any, flag: int) -> bool:
    try:
        return bool(int(value) & int(flag))
    except (TypeError, ValueError):
        return False


def _kind(meta: Any, name: Any) -> str:
    meta_type = getattr(meta, "type", None) if meta is not None else None
    if meta_type is not None:
        if meta_type in (pytsk3.TSK_FS_META_TYPE_DIR, pytsk3.TSK_FS_META_TYPE_VIRT_DIR):
            return "dir"
        if meta_type in (pytsk3.TSK_FS_META_TYPE_REG, pytsk3.TSK_FS_META_TYPE_VIRT):
            return "file"
        if meta_type == pytsk3.TSK_FS_META_TYPE_LNK:
            return "symlink"
        if meta_type != pytsk3.TSK_FS_META_TYPE_UNDEF:
            return "other"
    name_type = getattr(name, "type", None)
    if name_type in (pytsk3.TSK_FS_NAME_TYPE_DIR, pytsk3.TSK_FS_NAME_TYPE_VIRT_DIR):
        return "dir"
    if name_type in (pytsk3.TSK_FS_NAME_TYPE_REG, pytsk3.TSK_FS_NAME_TYPE_VIRT):
        return "file"
    if name_type == pytsk3.TSK_FS_NAME_TYPE_LNK:
        return "symlink"
    return "other"


def _status(name: Any, meta: Any) -> str:
    if not _flag(getattr(name, "flags", 0), pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
        return "allocated"
    if meta is None or not getattr(meta, "addr", 0):
        return "deleted_metadata_lost"
    if _flag(getattr(meta, "flags", 0), pytsk3.TSK_FS_META_FLAG_ALLOC):
        return "deleted_inode_reused"
    return "deleted"


def _time(meta: Any, field: str) -> int | None:
    value = getattr(meta, field, 0) if meta is not None else 0
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value or None


def _entry(entry: Any, parent_path: str) -> dict[str, Any] | None:
    info = getattr(entry, "info", None)
    name = getattr(info, "name", None)
    if name is None:
        return None
    try:
        text = name.name.decode("utf-8", errors="replace")
    except Exception:
        return None
    if text in {".", ".."}:
        return None
    meta = getattr(info, "meta", None)
    status = _status(name, meta)
    trusted_meta = meta if status != "deleted_inode_reused" else None
    inode = getattr(meta, "addr", None) if meta is not None else None
    if not inode:
        inode = getattr(name, "meta_addr", None) or None
    return {
        "name": text,
        "path": f"{parent_path.rstrip('/')}/{text}",
        "inode": int(inode) if inode else None,
        "kind": _kind(trusted_meta, name),
        "status": status,
        "size": int(getattr(trusted_meta, "size", 0) or 0) if trusted_meta is not None else None,
        "mode": int(getattr(trusted_meta, "mode", 0) or 0) if trusted_meta is not None else None,
        "uid": getattr(trusted_meta, "uid", None) if trusted_meta is not None else None,
        "gid": getattr(trusted_meta, "gid", None) if trusted_meta is not None else None,
        "mtime": _time(trusted_meta, "mtime"),
        "atime": _time(trusted_meta, "atime"),
        "ctime": _time(trusted_meta, "ctime"),
        "crtime": _time(trusted_meta, "crtime"),
    }


def _open_dir(fs_info: pytsk3.FS_Info, *, inode: int | None, path: str | None):
    try:
        if inode is not None:
            return fs_info.open_dir(inode=int(inode))
        return fs_info.open_dir(path=path or "/")
    except Exception as exc:
        raise BrowserError("directory_unreadable", f"The directory could not be read: {exc}") from exc


def _directory_inode(directory) -> int | None:
    addr = getattr(getattr(getattr(getattr(directory, "info", None), "fs_file", None), "meta", None), "addr", None)
    try:
        return int(addr) if addr is not None else None
    except (TypeError, ValueError):
        return None


def _iter_entries(directory, parent_path: str):
    parent_inode = _directory_inode(directory)
    for raw in directory:
        try:
            entry = _entry(raw, parent_path)
        except Exception:
            continue
        if entry is not None:
            entry["parent_inode"] = parent_inode
            yield entry


def _journal(fs_info) -> ExtJournal | None:
    """The ext3/ext4 journal index, or None (not ext, no journal, unreadable)."""
    if "journal" not in _context:
        _context["journal"] = None
        request = _context.get("request") or {}
        if request.get("journal", True):
            try:
                journal = ExtJournal(_volume_byte_reader(_context["reader"], _context["spec"]), fs_info, cache_path=request.get("journal_cache"))
                if journal.copies:
                    _context["journal"] = journal
            except Exception:
                pass
    return _context["journal"]


def _directory_blocks(fs_info, inode: int) -> list[int]:
    try:
        handle = fs_info.open_meta(inode=int(inode))
        return [block for attribute in handle for run in attribute for block in range(int(run.addr), int(run.addr) + int(run.len))]
    except Exception:
        return []


def _journal_entry(item: dict[str, Any], parent_path: str, parent_inode: int | None) -> dict[str, Any]:
    return {
        "name": item["name"],
        "path": f"{parent_path.rstrip('/')}/{item['name']}",
        "inode": item["inode"],
        "parent_inode": parent_inode,
        "kind": item["kind"],
        "status": "deleted_journal",
        "size": None, "mode": None, "uid": None, "gid": None, "mtime": None, "atime": None, "ctime": None, "crtime": None,
        "journal_last_seen": item.get("last_seen"),
        "journal_gone_by": item.get("gone_by"),
        "journal_first_seq": item.get("first_seq"),
        "journal_last_seq": item.get("last_seq"),
    }


def _journal_entries(fs_info, directory_inode: int | None, parent_path: str, live: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Names the journal remembers in this directory that it no longer lists."""
    journal = _journal(fs_info)
    if journal is None or directory_inode is None:
        return []
    present = {(entry["name"], entry["inode"]) for entry in live}
    names = journal.past_names(_directory_blocks(fs_info, directory_inode))
    return [_journal_entry(item, parent_path, directory_inode) for key, item in sorted(names.items()) if key not in present]


def _resolve(fs_info, item: dict[str, Any]) -> dict[str, Any] | None:
    """Look the item up again in its parent directory, so what gets exported
    and how it is labelled come from the filesystem, never from the request."""
    path = str(item.get("path") or "")
    parent_path, _, name = path.rpartition("/")
    parent_path = parent_path or "/"
    wanted = item.get("inode")
    live: list[dict[str, Any]] = []
    parent_inode = item.get("parent_inode")
    try:
        directory = _open_dir(fs_info, inode=parent_inode, path=parent_path)
        parent_inode = _directory_inode(directory)
        live = list(_iter_entries(directory, parent_path))
    except BrowserError:
        pass
    for entry in [*live, *_journal_entries(fs_info, parent_inode, parent_path, live)]:
        if entry["name"] == name and (wanted is None or entry["inode"] == wanted):
            return entry
    return None


def op_list(fs_info: pytsk3.FS_Info, request: dict[str, Any]) -> dict[str, Any]:
    path = request.get("path") or "/"
    inode = request.get("inode")
    if inode is None and path == "/":
        inode = int(fs_info.info.root_inum)
    directory = _open_dir(fs_info, inode=inode, path=path)
    limit = int(request.get("max_entries") or 10000)
    live = list(_iter_entries(directory, path))
    every = [*live, *_journal_entries(fs_info, _directory_inode(directory), path, live)]
    entries = every[:limit]
    return {"path": path, "inode": inode, "entries": entries, "total": len(every), "truncated": len(every) > len(entries), "journal": _journal(fs_info) is not None}


def _walk(fs_info, path: str, inode: int | None, *, include_deleted: bool, ancestors: set[int], budget: dict[str, int], depth: int = 0):
    """Allocated subdirectories only are descended into: a deleted directory
    name may point at a recycled inode, which can be one of its own ancestors
    (the same reason _iter_directory in the service skips them)."""
    if depth > 64 or budget["entries"] <= 0:
        return
    try:
        directory = _open_dir(fs_info, inode=inode, path=path)
    except BrowserError:
        return
    if inode is not None:
        ancestors.add(inode)
    try:
        for entry in _iter_entries(directory, path):
            budget["entries"] -= 1
            if budget["entries"] <= 0:
                budget["exhausted"] = 1
                return
            if entry["status"] != "allocated" and not include_deleted:
                continue
            yield entry
            child = entry["inode"]
            if entry["kind"] == "dir" and entry["status"] == "allocated" and child is not None and child not in ancestors:
                yield from _walk(fs_info, entry["path"], child, include_deleted=include_deleted, ancestors=ancestors, budget=budget, depth=depth + 1)
    finally:
        if inode is not None:
            ancestors.discard(inode)


def op_find(fs_info: pytsk3.FS_Info, request: dict[str, Any]) -> dict[str, Any]:
    raw = str(request.get("pattern") or "").strip()
    if not raw:
        raise BrowserError("empty_pattern", "Type part of a name or a glob such as *.php.")
    pattern = raw.lower() if any(ch in raw for ch in "*?[") else f"*{raw.lower()}*"
    match_path = "/" in raw
    start = request.get("path") or "/"
    start_inode = request.get("inode")
    if start_inode is None and start == "/":
        start_inode = int(fs_info.info.root_inum)
    max_results = int(request.get("max_results") or 500)
    budget = {"entries": int(request.get("max_entries_scanned") or 2_000_000), "exhausted": 0}
    include_deleted = bool(request.get("include_deleted"))
    results: list[dict[str, Any]] = []
    scanned = 0
    directories: dict[int, str] = {start_inode: start} if start_inode is not None else {}
    live: set[tuple[int | None, str, int | None]] = set()
    parent_of: dict[tuple[str, int | None], int | None] = {}

    def matches(entry: dict[str, Any]) -> bool:
        target = entry["path"].lower() if match_path else entry["name"].lower()
        return fnmatch.fnmatchcase(target, pattern)

    for entry in _walk(fs_info, start, start_inode, include_deleted=include_deleted, ancestors=set(), budget=budget):
        scanned += 1
        live.add((entry.get("parent_inode"), entry["name"], entry["inode"]))
        if entry["status"] == "allocated":
            parent_of[(entry["name"], entry["inode"])] = entry.get("parent_inode")
        if entry["kind"] == "dir" and entry["status"] == "allocated" and entry["inode"] is not None:
            directories.setdefault(entry["inode"], entry["path"])
        if matches(entry):
            results.append(entry)
            if len(results) >= max_results:
                return {"results": results, "scanned": scanned, "truncated": True}
    journal = _journal(fs_info) if include_deleted else None
    if journal is not None:
        seen: set[tuple[int, str, int]] = set()
        for number, owner, names in journal.journaled_directory_blocks():
            # Only a directory's first block starts with "."; any other block
            # is placed by a name it holds that is still live somewhere.
            if owner is None:
                owner = next((parent_of[(name, inode)] for name, inode, _, _ in names if (name, inode) in parent_of), None)
            if owner is None:
                owner = next((parent_of[(name, inode)] for inode, _, name in journal.dirents(journal.block(number)) if (name, inode) in parent_of), None)
            if owner is None or (owner not in directories and start != "/"):
                continue
            parent_path = directories.get(owner, f"/<deleted directory {owner}>")
            for (name, inode), item in journal.past_names([number]).items():
                key = (owner, name, inode)
                if key in live or key in seen:
                    continue
                seen.add(key)
                entry = _journal_entry(item, parent_path, owner)
                if matches(entry):
                    results.append(entry)
                    if len(results) >= max_results:
                        return {"results": results, "scanned": scanned, "truncated": True}
    return {"results": results, "scanned": scanned, "truncated": bool(budget["exhausted"])}


def _safe_component(name: str) -> str:
    cleaned = _UNSAFE_NAME.sub("_", name).strip()
    if cleaned in {"", ".", ".."}:
        cleaned = f"_{cleaned}" if cleaned else "_"
    return cleaned[:200]


def _write_from_journal(journal: ExtJournal, recovered: dict[str, Any], record: dict[str, Any], destination: Path, budget: dict[str, int]) -> dict[str, Any]:
    size = recovered["size"]
    times = {key: recovered.get(key) or None for key in ("mtime", "atime", "ctime", "crtime")}
    record = {**record, **times, "size": size, "uid": recovered["uid"], "gid": recovered["gid"], "method": "ext_journal",
              "journal_seq": recovered["seq"], "journal_committed": recovered["committed"], "blocks": recovered["blocks"], "blocks_reused": recovered["blocks_reused"]}
    if size > budget["bytes"]:
        return {**record, "result": "skipped", "reason": "Over the export size limit."}
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    written = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as out:
        for chunk in journal.iter_content(recovered):
            sha256.update(chunk)
            md5.update(chunk)
            out.write(chunk)
            written += len(chunk)
    budget["bytes"] -= written
    record = {**record, "bytes_written": written, "sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
    source = f"Rebuilt from a copy of its inode in the ext journal (transaction {recovered['seq']})."
    if written < size:
        return {**record, "result": "partial", "reason": f"{source} The volume ended at byte {written}."}
    if recovered["blocks_reused"]:
        return {**record, "result": "suspect", "reason": f"{source} {recovered['blocks_reused']} of its {recovered['blocks']} blocks now belong to other files, so part of the content is probably theirs."}
    return {**record, "result": "recovered", "reason": f"{source} None of its {recovered['blocks']} blocks has been given to another file since."}


def _export_one(fs_info, entry: dict[str, Any], destination: Path, budget: dict[str, int]) -> dict[str, Any]:
    record = {key: entry.get(key) for key in ("path", "inode", "status", "size", "mtime", "atime", "ctime", "crtime")}
    status = entry.get("status")
    if status == "deleted_journal":
        journal = _journal(fs_info)
        if entry.get("journal_last_seq") is None:
            return {**record, "result": "unrecoverable", "reason": "The journal only holds this name as an already-deleted record, so when it existed (and which version of its inode was its) is unknown."}
        recovered = journal.recover(int(entry["inode"]), min_seq=entry.get("journal_first_seq"), max_seq=entry.get("journal_last_seq")) if journal and entry.get("kind") == "file" else None
        if recovered is None:
            return {**record, "result": "unrecoverable", "reason": "The journal has the name, but no copy of its inode from while the name existed and the file still had content."}
        return _write_from_journal(journal, recovered, record, destination, budget)
    if status == "deleted_inode_reused":
        return {**record, "result": "skipped", "reason": "The inode now belongs to another file, so its content is not this file's."}
    if status == "deleted_metadata_lost" or not entry.get("inode"):
        return {**record, "result": "skipped", "reason": "Only the name survives; there is no metadata pointing at the content."}
    if entry.get("kind") != "file":
        return {**record, "result": "skipped", "reason": f"Not a regular file ({entry.get('kind')})."}
    try:
        handle = fs_info.open_meta(inode=int(entry["inode"]))
    except Exception as exc:
        return {**record, "result": "failed", "reason": f"The file could not be opened: {exc}"}
    meta = handle.info.meta
    size = int(getattr(meta, "size", 0) or 0)
    if size > budget["bytes"]:
        return {**record, "size": size, "result": "skipped", "reason": "Over the export size limit."}
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    written = 0
    nonzero = False
    reason = ""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as out:
        while written < size:
            length = min(_CHUNK, size - written)
            try:
                chunk = handle.read_random(written, length)
            except Exception as exc:
                reason = f"Read stopped at byte {written}: {exc}"
                break
            if not chunk:
                reason = f"Read stopped at byte {written}."
                break
            nonzero = nonzero or any(chunk)
            sha256.update(chunk)
            md5.update(chunk)
            out.write(chunk)
            written += len(chunk)
    budget["bytes"] -= written
    result = {**record, "size": size, "bytes_written": written, "sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
    if status == "deleted" and (size == 0 or written == 0 or not nonzero):
        # ext3/ext4 clear the inode on delete; an older copy in the journal may still point at the content.
        journal = _journal(fs_info)
        if journal is not None:
            try:
                generation = journal.inode_on_disk(int(entry["inode"]))["generation"]
                recovered = journal.recover(int(entry["inode"]), generation=generation)
            except Exception:
                recovered = None
            if recovered is not None:
                return _write_from_journal(journal, recovered, record, destination, budget)
    if written == 0 and size > 0:
        destination.unlink(missing_ok=True)
        return {**result, "result": "unrecoverable", "reason": reason or "No content could be read.", "sha256": None, "md5": None}
    if status == "deleted" and size == 0:
        destination.unlink(missing_ok=True)
        return {**result, "result": "unrecoverable", "reason": "The filesystem cleared the size and block pointers when it deleted the file (usual on ext3/ext4), and the journal has no older copy of its inode.", "sha256": None, "md5": None}
    if written < size:
        return {**result, "result": "partial", "reason": reason}
    if status == "deleted" and size and not nonzero:
        return {**result, "result": "suspect", "reason": "Every byte read back as zero: the blocks were probably released or overwritten."}
    if status == "deleted":
        return {**result, "result": "recovered", "reason": "Deleted file read through its surviving inode; the blocks may since have been reused."}
    return {**result, "result": "exported", "reason": ""}


def op_export(fs_info: pytsk3.FS_Info, request: dict[str, Any]) -> dict[str, Any]:
    output_dir = Path(request["output_dir"])
    files_root = output_dir / "files"
    files_root.mkdir(parents=True, exist_ok=True)
    include_deleted = bool(request.get("include_deleted"))
    budget = {"bytes": int(request.get("max_bytes") or 2 * 1024**3), "files": int(request.get("max_files") or 5000)}
    used: set[str] = set()
    manifest: list[dict[str, Any]] = []
    truncated = False

    def target_for(entry: dict[str, Any]) -> Path:
        parts = [_safe_component(part) for part in entry["path"].split("/") if part]
        relative = "/".join(parts) or "_"
        if relative in used:
            relative = f"{relative}~{entry.get('inode')}"
        used.add(relative)
        return files_root / relative

    def export(entry: dict[str, Any]) -> None:
        nonlocal truncated
        if budget["files"] <= 0 or budget["bytes"] <= 0:
            truncated = True
            return
        budget["files"] -= 1
        destination = target_for(entry)
        record = _export_one(fs_info, entry, destination, budget)
        if destination.exists():
            record["archive_path"] = destination.relative_to(output_dir).as_posix()
        manifest.append(record)

    for item in request.get("items") or []:
        entry = _resolve(fs_info, item)
        if entry is None:
            manifest.append({"path": item.get("path"), "inode": item.get("inode"), "result": "skipped", "reason": "Not found in its directory any more."})
            continue
        if entry.get("kind") == "dir":
            if entry.get("status") != "allocated":
                manifest.append({"path": entry.get("path"), "inode": entry.get("inode"), "result": "skipped", "reason": "Deleted directories are not walked; export its files one by one."})
                continue
            walk_budget = {"entries": 2_000_000, "exhausted": 0}
            for child in _walk(fs_info, entry["path"], entry.get("inode"), include_deleted=include_deleted, ancestors=set(), budget=walk_budget):
                if child["kind"] == "file" or (child["kind"] != "dir" and child["status"] != "allocated"):
                    export(child)
                if truncated:
                    break
        else:
            export(entry)
        if truncated:
            break
    return {"manifest": manifest, "truncated": truncated}


_OPERATIONS = {"list": op_list, "find": op_find, "export": op_export}


def run(request: dict[str, Any]) -> dict[str, Any]:
    operation = _OPERATIONS.get(str(request.get("op")))
    if operation is None:
        raise BrowserError("unknown_operation", f"Unknown operation {request.get('op')!r}.")
    reader, fs_info = _open_fs(request)
    try:
        return operation(fs_info, request)
    finally:
        reader.close()


def main() -> int:
    try:
        response = run(json.loads(sys.stdin.read()))
    except BrowserError as exc:
        response = {"error": exc.code, "message": exc.message}
    except Exception as exc:  # anything else is reported, never a traceback on stdout
        response = {"error": "explorer_failed", "message": str(exc)}
    sys.stdout.write(json.dumps(response, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
