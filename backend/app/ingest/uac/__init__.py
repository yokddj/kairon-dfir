"""UAC (Unix-like Artifacts Collector) collections.

UAC (https://github.com/tclahr/uac) writes one tar per run with the same layout on every
operating system it supports: the collected files under ``[root]/``, command output under
``live_response/``, ``bodyfile/bodyfile.txt``, ``hash_executables/``, find-based listings under
``system/`` and its own ``uac.log``. This package recognises that layout and parses the parts that
do not depend on the operating system; the collected files themselves go to the macOS or Linux
artifact parsers.
"""
