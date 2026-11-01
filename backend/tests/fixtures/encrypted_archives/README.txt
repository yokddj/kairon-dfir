Encrypted RAR test fixtures, used to verify Kairon's RAR decryption (see
test_encrypted_archive.py). These contain no forensic data -- two small
text files ("stest1.txt"/"stest2.txt" or "file1.txt"/"file2.txt") each,
compressed and encrypted with the password "password".

Source: the rarfile Python project's own test suite.
https://github.com/markokr/rarfile/tree/master/test/files
Copyright (c) 2005-2026 Marko Kreen <markokr@gmail.com>, ISC license (see
below); redistributed unmodified under that license.

    Permission to use, copy, modify, and/or distribute this software for
    any purpose with or without fee is hereby granted, provided that the
    above copyright notice and this permission notice appear in all
    copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.

Files:
- rar5-psw.rar: RAR5, content encrypted, header plain (lists members
  without a password).
- rar5-hpsw.rar: RAR5, header encrypted too (member names need the
  password to read).

(rar3-comment-psw.rar / rar3-comment-hpsw.rar from the same suite were
tried too, but their members are 0 bytes -- an empty file decrypts to
nothing with any password, so a wrong one cannot be told apart. unar/lsar
do not distinguish RAR3 from RAR5 in Kairon's code, so RAR5 fixtures alone
exercise the same code path.)

This file is supporting documentation and must not be indexed as
forensic events.
