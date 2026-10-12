"""ExtJournal on a hand-built ext volume and jbd2 journal (1 KiB blocks).

Story: /secret.c (inode 12, content in block 20) is listed in directory
block 30 in transaction 10 and gone in transaction 11. On the volume as it is
now, the directory no longer lists it and the inode is cleared, like ext3/ext4
leave a deleted file."""

from __future__ import annotations

import struct
from types import SimpleNamespace

from app.disk_images.ext_journal import ExtJournal

BS = 1024
CONTENT = b"int main() { return 0; }\n"


def _dirent(inode: int, name: bytes, rec_len: int, file_type: int = 1) -> bytes:
    return struct.pack("<IHBB", inode, rec_len, len(name), file_type) + name + b"\0" * (rec_len - 8 - len(name))


def _directory(with_secret: bool) -> bytes:
    dot = _dirent(2, b".", 12, 2)
    dotdot = _dirent(2, b"..", 12, 2)
    keep = _dirent(11, b"keep.txt", 16)
    if with_secret:
        return dot + dotdot + keep + _dirent(12, b"secret.c", BS - 40)
    # Deleting the last record extends the previous one over it; its bytes stay as slack.
    return dot + dotdot + struct.pack("<IHBB", 11, BS - 24, 8, 1) + b"keep.txt" + _dirent(12, b"secret.c", BS - 40)


def _inode(*, live: bool) -> bytes:
    raw = bytearray(128)
    if live:
        struct.pack_into("<HHIIIIIHH", raw, 0, 0x81A4, 33, len(CONTENT), 1, 2, 3, 0, 33, 1)
        struct.pack_into("<I", raw, 0x28, 20)  # first direct block pointer
    else:
        struct.pack_into("<HHIIIIIHH", raw, 0, 0x81A4, 33, 0, 1, 2, 3, 99, 33, 0)
    struct.pack_into("<I", raw, 0x64, 7)  # generation
    return bytes(raw)


def _inode_table(*, live: bool) -> bytes:
    table = bytearray(BS)
    offset = (12 - 1) * 128 % BS
    table[offset:offset + 128] = _inode(live=live)
    return bytes(table)


def _volume() -> bytearray:
    volume = bytearray(64 * BS)
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x0, 16)  # inodes
    struct.pack_into("<I", sb, 0x14, 1)  # first data block
    struct.pack_into("<I", sb, 0x18, 0)  # 1 KiB blocks
    struct.pack_into("<I", sb, 0x20, 8192)  # blocks per group
    struct.pack_into("<I", sb, 0x28, 16)  # inodes per group
    struct.pack_into("<H", sb, 0x38, 0xEF53)
    struct.pack_into("<I", sb, 0x4C, 1)
    struct.pack_into("<H", sb, 0x58, 128)
    struct.pack_into("<I", sb, 0xE0, 8)  # journal inode
    volume[1024:2048] = sb
    descriptor = bytearray(32)
    struct.pack_into("<I", descriptor, 0x0, 3)  # block bitmap
    struct.pack_into("<I", descriptor, 0x8, 4)  # inode table: inode 12 lands in block 5
    volume[2 * BS:2 * BS + 32] = descriptor
    volume[5 * BS:6 * BS] = _inode_table(live=False)
    volume[20 * BS:20 * BS + len(CONTENT)] = CONTENT
    volume[30 * BS:31 * BS] = _directory(with_secret=False)
    return volume


def _header(blocktype: int, seq: int) -> bytes:
    return struct.pack(">III", 0xC03B3998, blocktype, seq)


def _descriptor(seq: int, fs_blocks: list[int]) -> bytes:
    block = bytearray(BS)
    block[0:12] = _header(1, seq)
    offset = 12
    for index, number in enumerate(fs_blocks):
        flags = 2 | (8 if index == len(fs_blocks) - 1 else 0)  # same UUID, last tag
        struct.pack_into(">IHH", block, offset, number, 0, flags)
        offset += 8
    return bytes(block)


def _commit(seq: int, seconds: int) -> bytes:
    block = bytearray(BS)
    block[0:12] = _header(2, seq)
    struct.pack_into(">Q", block, 0x30, seconds)
    return bytes(block)


def _journal() -> bytes:
    superblock = bytearray(BS)
    superblock[0:12] = _header(4, 0)
    struct.pack_into(">III", superblock, 0xC, BS, 16, 1)
    blocks = [
        bytes(superblock),
        _descriptor(10, [30, 5]), _directory(with_secret=True), _inode_table(live=True), _commit(10, 1_570_274_625),
        _descriptor(11, [30]), _directory(with_secret=False), _commit(11, 1_570_274_632),
    ]
    return b"".join(blocks).ljust(16 * BS, b"\0")


class _File:
    def __init__(self, data: bytes):
        self.data = data
        self.info = SimpleNamespace(meta=SimpleNamespace(size=len(data)))

    def read_random(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]


def _journal_over(volume: bytearray) -> ExtJournal:
    fs_info = SimpleNamespace(open_meta=lambda inode: _File(_journal()))
    return ExtJournal(lambda offset, size: bytes(volume[offset:offset + size]), fs_info)


def test_a_name_the_directory_lost_is_found_with_its_lifetime():
    names = _journal_over(_volume()).past_names([30])
    secret = names[("secret.c", 12)]
    assert (secret["first_seq"], secret["last_seq"], secret["gone_seq"]) == (10, 10, 11)
    assert (secret["last_seen"], secret["gone_by"]) == (1_570_274_625, 1_570_274_632)
    assert secret["kind"] == "file"


def test_content_is_rebuilt_from_the_old_inode_copy():
    journal = _journal_over(_volume())
    recovered = journal.recover(12, min_seq=10, max_seq=10)
    assert recovered is not None and recovered["blocks_reused"] == 0
    assert b"".join(journal.iter_content(recovered)) == CONTENT
    assert (recovered["uid"], recovered["mtime"]) == (33, 3)


def test_blocks_given_to_another_file_are_reported():
    volume = _volume()
    volume[3 * BS + (20 - 1) // 8] |= 1 << ((20 - 1) % 8)  # block 20 allocated again
    recovered = _journal_over(volume).recover(12, min_seq=10, max_seq=10)
    assert recovered["blocks_reused"] == 1


def test_an_inode_copy_outside_the_names_lifetime_is_not_used():
    # Transaction 10 is the only live copy of inode 12; a name seen only later must not claim it.
    assert _journal_over(_volume()).recover(12, min_seq=11, max_seq=11) is None
    # A different generation is a different file.
    assert _journal_over(_volume()).recover(12, generation=8) is None
