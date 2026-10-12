"""Deleted names and file content from the ext3/ext4 journal (jbd2).

When ext3/ext4 delete a file they reuse its directory slot and clear the
inode's size and block pointers, so the live filesystem has nothing left to
read. The journal, however, keeps whole copies of the metadata blocks it
wrote: directory blocks from before the name was removed, and inode table
blocks from before the inode was cleared. This module indexes those copies
and rebuilds from them

- the names a directory held in the past (with the inode they pointed at and
  when they were last seen), and
- a deleted file's content, by reading the block list from an old copy of
  its inode and then those blocks from the volume.

Data blocks themselves are not journaled (default "ordered" mode), so they
are read from the volume as they are now: once the filesystem has given them
to another file, the content is gone. recover() reports how many of the
blocks are allocated again, which is the measure of how much to trust it.

Read-only; works on raw bytes because TSK exposes neither the journal's
structure nor raw block reads."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct
from typing import Any, Callable, Iterator

_EXT_MAGIC = 0xEF53
_JBD2_MAGIC = 0xC03B3998
_DESCRIPTOR, _COMMIT, _SB_V1, _SB_V2, _REVOKE = 1, 2, 3, 4, 5
_FLAG_ESCAPE, _FLAG_SAME_UUID, _FLAG_LAST_TAG = 1, 2, 8
_INCOMPAT_64BIT, _INCOMPAT_CSUM_V2, _INCOMPAT_CSUM_V3 = 0x2, 0x8, 0x10
_EXTENTS_FL = 0x80000
_EXTENT_MAGIC = 0xF30A
_FILE_TYPES = {1: "file", 2: "dir", 7: "symlink"}
_INDEX_VERSION = 2


@dataclass
class _Copy:
    seq: int
    journal_block: int
    escaped: bool


class ExtJournal:
    def __init__(self, read: Callable[[int, int], bytes], fs_info: Any, *, cache_path: str | None = None):
        self._read = read
        sb = read(1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != _EXT_MAGIC:
            raise ValueError("not an ext2/3/4 filesystem")
        self.inode_count = struct.unpack_from("<I", sb, 0x0)[0]
        self.block_size = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 0x20)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        revision = struct.unpack_from("<I", sb, 0x4C)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] if revision >= 1 else 128
        incompat = struct.unpack_from("<I", sb, 0x60)[0]
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] if incompat & 0x80 else 32
        self.desc_size = self.desc_size or 32
        self.journal_inum = struct.unpack_from("<I", sb, 0xE0)[0]
        self._fs_info = fs_info
        self._journal = None
        self.copies: dict[int, list[_Copy]] = {}
        self.commit_times: dict[int, int] = {}
        # fs block -> [(seq, owner inode or None, [[name, inode, file_type, live], ...])]
        # for every journal copy that is a directory block, parsed once at index time.
        self.dir_copies: dict[int, list[tuple[int, int | None, list[list[Any]]]]] = {}
        if self.journal_inum:
            self._journal = fs_info.open_meta(inode=self.journal_inum)
            self._load_index(cache_path)

    # -- volume -----------------------------------------------------------
    def block(self, number: int) -> bytes:
        return self._read(number * self.block_size, self.block_size)

    def _group_descriptor(self, group: int) -> bytes:
        gdt_block = self.first_data_block + 1
        offset = gdt_block * self.block_size + group * self.desc_size
        return self._read(offset, self.desc_size)

    def _desc_block(self, desc: bytes, lo: int, hi: int) -> int:
        value = struct.unpack_from("<I", desc, lo)[0]
        if self.desc_size >= 64:
            value |= struct.unpack_from("<I", desc, hi)[0] << 32
        return value

    def inode_location(self, inode: int) -> tuple[int, int]:
        group, index = divmod(inode - 1, self.inodes_per_group)
        table = self._desc_block(self._group_descriptor(group), 0x8, 0x28)
        block, offset = divmod(index * self.inode_size, self.block_size)
        return table + block, offset

    def block_allocated(self, number: int) -> bool:
        group, index = divmod(number - self.first_data_block, self.blocks_per_group)
        bitmap = self.block(self._desc_block(self._group_descriptor(group), 0x0, 0x20))
        return bool(bitmap[index // 8] & (1 << (index % 8)))

    # -- journal index ------------------------------------------------------
    def _journal_read(self, block: int, count: int = 1) -> bytes:
        return self._journal.read_random(block * self._jbs, count * self._jbs)

    def _load_index(self, cache_path: str | None) -> None:
        header = self._journal.read_random(0, 1024)
        magic, blocktype, _ = struct.unpack_from(">III", header, 0)
        if magic != _JBD2_MAGIC or blocktype not in (_SB_V1, _SB_V2):
            return
        self._jbs, maxlen, first = struct.unpack_from(">III", header, 0xC)
        incompat = struct.unpack_from(">I", header, 0x28)[0] if blocktype == _SB_V2 else 0
        cache = Path(cache_path) if cache_path else None
        if cache and cache.exists():
            try:
                data = json.loads(cache.read_text())
                if data.get("version") == _INDEX_VERSION:
                    self.copies = {int(k): [_Copy(*item) for item in v] for k, v in data["copies"].items()}
                    self.commit_times = {int(k): v for k, v in data["commit_times"].items()}
                    self.dir_copies = {int(k): [tuple(item) for item in v] for k, v in data["dir_copies"].items()}
                    return
            except (OSError, ValueError, KeyError, TypeError):
                pass
        self._scan(maxlen, first, incompat)
        self._index_directories(maxlen)
        if cache:
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps({
                    "version": _INDEX_VERSION,
                    "copies": {k: [[c.seq, c.journal_block, c.escaped] for c in v] for k, v in self.copies.items()},
                    "commit_times": self.commit_times,
                    "dir_copies": self.dir_copies,
                }))
            except OSError:
                pass

    def _scan(self, maxlen: int, first: int, incompat: int) -> None:
        """Every descriptor block in the whole log, not only the transactions
        a replay would apply: older, already-checkpointed transactions are
        exactly the history wanted here."""
        if incompat & _INCOMPAT_CSUM_V3:
            tag_size = 16
        else:
            tag_size = 12 if incompat & _INCOMPAT_64BIT else 8
        tail = 4 if incompat & (_INCOMPAT_CSUM_V2 | _INCOMPAT_CSUM_V3) else 0
        chunk = 1024
        block = first
        while block < maxlen:
            count = min(chunk, maxlen - block)
            data = self._journal_read(block, count)
            index = 0
            while index < count:
                position = index * self._jbs
                magic, blocktype, seq = struct.unpack_from(">III", data, position)
                if magic != _JBD2_MAGIC:
                    index += 1
                    continue
                if blocktype == _COMMIT:
                    seconds = struct.unpack_from(">Q", data, position + 0x30)[0]
                    if seconds:
                        self.commit_times[seq] = seconds
                    index += 1
                    continue
                if blocktype != _DESCRIPTOR:
                    index += 1
                    continue
                tags = self._tags(data[position:position + self._jbs], tag_size, tail)
                for number, (fs_block, escaped) in enumerate(tags, start=1):
                    journal_block = block + index + number
                    if journal_block < maxlen:
                        self.copies.setdefault(fs_block, []).append(_Copy(seq, journal_block, escaped))
                index += 1 + len(tags)
            block += index if index > count else count
        for items in self.copies.values():
            items.sort(key=lambda copy: copy.seq)

    def _index_directories(self, maxlen: int) -> None:
        """One sequential pass over the journal parsing every copy that is a
        directory block, so listing and search never re-read the journal."""
        targets: dict[int, tuple[int, _Copy]] = {}
        for fs_block, copies in self.copies.items():
            for copy in copies:
                targets[copy.journal_block] = (fs_block, copy)
        chunk = 1024
        for start in range(0, maxlen, chunk):
            wanted = [block for block in range(start, min(start + chunk, maxlen)) if block in targets]
            if not wanted:
                continue
            data = self._journal_read(start, min(chunk, maxlen - start))
            for journal_block in wanted:
                fs_block, copy = targets[journal_block]
                raw = data[(journal_block - start) * self._jbs:(journal_block - start + 1) * self._jbs]
                if copy.escaped:
                    raw = struct.pack(">I", _JBD2_MAGIC) + raw[4:]
                if len(raw) != self._jbs or not self.looks_like_directory_block(raw):
                    continue
                live = self.live_dirents(raw)
                entries = [[name, inode, file_type, (name, inode) in live] for inode, file_type, name in self.dirents(raw)]
                self.dir_copies.setdefault(fs_block, []).append((copy.seq, self.directory_owner(raw), entries))
        for items in self.dir_copies.values():
            items.sort(key=lambda item: item[0])

    def _tags(self, descriptor: bytes, tag_size: int, tail: int) -> list[tuple[int, bool]]:
        tags = []
        offset = 12
        limit = len(descriptor) - tail
        while offset + tag_size <= limit:
            if tag_size == 16:
                low, flags, high = struct.unpack_from(">III", descriptor, offset)
            else:
                low = struct.unpack_from(">I", descriptor, offset)[0]
                flags = struct.unpack_from(">H", descriptor, offset + 6)[0]
                high = struct.unpack_from(">I", descriptor, offset + 8)[0] if tag_size == 12 else 0
            tags.append(((high << 32) | low, bool(flags & _FLAG_ESCAPE)))
            offset += tag_size
            if not flags & _FLAG_SAME_UUID:
                offset += 16
            if flags & _FLAG_LAST_TAG:
                break
        return tags

    def copy_data(self, copy: _Copy) -> bytes:
        data = self._journal_read(copy.journal_block)
        if copy.escaped:
            data = struct.pack(">I", _JBD2_MAGIC) + data[4:]
        return data

    def block_as_of(self, number: int, max_seq: int | None) -> bytes:
        """The newest journal copy of a block not after max_seq, else the block on disk."""
        for copy in reversed(self.copies.get(number, [])):
            if max_seq is None or copy.seq <= max_seq:
                return self.copy_data(copy)
        return self.block(number)

    # -- directories --------------------------------------------------------
    def dirents(self, data: bytes) -> Iterator[tuple[int, int, str]]:
        """Live and deleted records alike: every 4-byte aligned offset that
        holds a plausible entry. A deleted record keeps its bytes until the
        slot is reused; only the previous record's length hides it."""
        size = len(data)
        for offset in range(0, size - 8, 4):
            inode, rec_len, name_len, file_type = struct.unpack_from("<IHBB", data, offset)
            if not inode or inode > self.inode_count or not name_len or file_type > 7:
                continue
            if rec_len < 8 + name_len or rec_len % 4 or offset + rec_len > size:
                continue
            raw = data[offset + 8: offset + 8 + name_len]
            if b"\0" in raw or b"/" in raw:
                continue
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not name.isprintable() or name in {".", ".."}:
                continue
            yield inode, file_type, name

    def looks_like_directory_block(self, data: bytes) -> bool:
        offset = 0
        size = len(data)
        while offset < size:
            if offset + 8 > size:
                return False
            rec_len, name_len = struct.unpack_from("<HB", data, offset + 4)
            if rec_len < 8 or rec_len % 4 or offset + rec_len > size or name_len + 8 > rec_len:
                return False
            offset += rec_len
        return offset == size

    def directory_owner(self, data: bytes) -> int | None:
        inode, rec_len, name_len, _ = struct.unpack_from("<IHBB", data, 0)
        if name_len == 1 and data[8:9] == b".":
            return inode
        return None

    def live_dirents(self, data: bytes) -> set[tuple[str, int]]:
        """The names the block listed at the time: its rec_len chain."""
        names: set[tuple[str, int]] = set()
        offset = 0
        while offset + 8 <= len(data):
            inode, rec_len, name_len, _ = struct.unpack_from("<IHBB", data, offset)
            if rec_len < 8:
                break
            if inode and name_len:
                try:
                    names.add((data[offset + 8: offset + 8 + name_len].decode("utf-8"), inode))
                except UnicodeDecodeError:
                    pass
            offset += rec_len
        return names

    def past_names(self, blocks: list[int]) -> dict[tuple[str, int], dict[str, Any]]:
        """(name, inode) -> what the journal knows about it, for the given
        directory blocks.

        first_seq/last_seq bound the transactions in which the directory
        listed the name. A name only ever seen as a deleted record (the slack
        of a copy) has none: its lifetime is unknown, so no inode copy can be
        tied to it."""
        found: dict[tuple[str, int], dict[str, Any]] = {}
        for number in blocks:
            history: list[tuple[int, set[tuple[str, int]]]] = []
            for seq, _, entries in self.dir_copies.get(number, []):
                live = {(name, inode) for name, inode, _, is_live in entries if is_live}
                for name, inode, file_type, is_live in entries:
                    item = found.setdefault((name, inode), {"name": name, "inode": inode, "kind": _FILE_TYPES.get(file_type, "other"), "first_seq": None, "last_seq": None})
                    if is_live:
                        item["first_seq"] = seq if item["first_seq"] is None else min(item["first_seq"], seq)
                        item["last_seq"] = seq if item["last_seq"] is None else max(item["last_seq"], seq)
                history.append((seq, live))
            for key, item in found.items():
                if item["last_seq"] is None:
                    continue
                later = [seq for seq, live in history if seq > item["last_seq"] and key not in live]
                if later:
                    item["gone_seq"] = min(later)
        for item in found.values():
            item["last_seen"] = self.commit_times.get(item["last_seq"]) if item["last_seq"] is not None else None
            item["gone_by"] = self.commit_times.get(item["gone_seq"]) if item.get("gone_seq") else None
        return found

    def journaled_directory_blocks(self) -> Iterator[tuple[int, int | None, list[list[Any]]]]:
        """(fs block, owner inode if a copy starts with ".", names any copy
        holds) for every directory block the journal has a copy of."""
        for number, copies in self.dir_copies.items():
            owner = next((item[1] for item in copies if item[1] is not None), None)
            yield number, owner, [entry for _, _, entries in copies for entry in entries]

    # -- inodes ---------------------------------------------------------------
    def _parse_inode(self, raw: bytes) -> dict[str, Any]:
        mode, uid, size_lo, atime, ctime, mtime, dtime, gid, links = struct.unpack_from("<HHIIIIIHH", raw, 0)
        flags = struct.unpack_from("<I", raw, 0x20)[0]
        size_hi = struct.unpack_from("<I", raw, 0x6C)[0]
        crtime = struct.unpack_from("<I", raw, 0x90)[0] if len(raw) >= 0x94 else 0
        return {
            "mode": mode, "uid": uid, "gid": gid, "size": size_lo | (size_hi << 32), "atime": atime, "ctime": ctime, "mtime": mtime,
            "crtime": crtime, "dtime": dtime, "links": links, "flags": flags, "i_block": raw[0x28:0x28 + 60],
            "generation": struct.unpack_from("<I", raw, 0x64)[0],
        }

    def inode_on_disk(self, inode: int) -> dict[str, Any]:
        block, offset = self.inode_location(inode)
        return self._parse_inode(self.block(block)[offset:offset + self.inode_size])

    def _block_map(self, info: dict[str, Any], seq: int) -> list[tuple[int, int, int]]:
        """(logical block, physical block, length) runs."""
        runs: list[tuple[int, int, int]] = []
        if info["flags"] & _EXTENTS_FL:
            self._extent_runs(info["i_block"], seq, runs, depth_guard=0)
        else:
            pointers = struct.unpack_from("<15I", info["i_block"], 0)
            per_block = self.block_size // 4
            logical = 0
            for pointer in pointers[:12]:
                if pointer:
                    runs.append((logical, pointer, 1))
                logical += 1
            for level, pointer in enumerate(pointers[12:15], start=1):
                logical = self._indirect_runs(pointer, level, logical, seq, runs, per_block)
        return runs

    def _indirect_runs(self, pointer: int, level: int, logical: int, seq: int, runs: list, per_block: int) -> int:
        span = per_block ** level
        if not pointer:
            return logical + span
        entries = struct.unpack(f"<{per_block}I", self.block_as_of(pointer, seq))
        for entry in entries:
            if level == 1:
                if entry:
                    runs.append((logical, entry, 1))
                logical += 1
            else:
                logical = self._indirect_runs(entry, level - 1, logical, seq, runs, per_block)
        return logical

    def _extent_runs(self, node: bytes, seq: int, runs: list, depth_guard: int) -> None:
        magic, entries, _, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != _EXTENT_MAGIC or depth_guard > 5:
            return
        for index in range(entries):
            offset = 12 + index * 12
            if offset + 12 > len(node):
                break
            if depth == 0:
                logical, length, start_hi, start_lo = struct.unpack_from("<IHHI", node, offset)
                uninitialized = length > 32768
                length = length - 32768 if uninitialized else length
                if not uninitialized:
                    runs.append((logical, (start_hi << 32) | start_lo, length))
            else:
                _, leaf_lo, leaf_hi = struct.unpack_from("<IIH", node, offset)
                self._extent_runs(self.block_as_of((leaf_hi << 32) | leaf_lo, seq), seq, runs, depth_guard + 1)

    def recover(self, inode: int, *, min_seq: int | None = None, max_seq: int | None = None, generation: int | None = None) -> dict[str, Any] | None:
        """Newest journal copy of the inode, from while it was a live regular
        file with content, and the block runs it pointed at. None when there
        is none.

        Which copies may be used is what ties the content to a name: an inode
        number is reused, so a copy from before or after the name existed
        describes some other file. A name seen in the journal passes the
        window it was seen in (min_seq..max_seq); a deleted name still in its
        directory passes the inode's generation on disk."""
        block, offset = self.inode_location(inode)
        for copy in reversed(self.copies.get(block, [])):
            if max_seq is not None and copy.seq > max_seq:
                continue
            if min_seq is not None and copy.seq < min_seq:
                break
            info = self._parse_inode(self.copy_data(copy)[offset:offset + self.inode_size])
            if info["mode"] & 0xF000 != 0x8000 or not info["links"] or info["dtime"] or not info["size"]:
                continue
            if generation is not None and info["generation"] != generation:
                continue
            runs = self._block_map(info, copy.seq)
            if not runs:
                continue
            blocks = sum(length for _, _, length in runs)
            reused = sum(1 for _, start, length in runs for number in range(start, start + length) if self.block_allocated(number))
            return {**info, "runs": runs, "seq": copy.seq, "committed": self.commit_times.get(copy.seq), "blocks": blocks, "blocks_reused": reused}
        return None

    def iter_content(self, recovered: dict[str, Any], chunk_blocks: int = 256) -> Iterator[bytes]:
        size = recovered["size"]
        mapping: dict[int, int] = {}
        for logical, start, length in recovered["runs"]:
            for step in range(length):
                mapping[logical + step] = start + step
        produced = 0
        logical = 0
        while produced < size:
            physical = mapping.get(logical)
            if physical is None:  # a hole: sparse files read back as zeros
                count = 1
                data = b"\0" * self.block_size
            else:
                count = 1
                while count < chunk_blocks and mapping.get(logical + count) == physical + count:
                    count += 1
                data = self._read(physical * self.block_size, count * self.block_size)
            logical += count
            data = data[: size - produced]
            if not data:  # past the end of the volume
                return
            produced += len(data)
            yield data
