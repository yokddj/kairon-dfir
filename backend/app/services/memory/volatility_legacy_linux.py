"""Run Volatility 3's command line with support for Linux kernels before 2.6.29.

Two places where Volatility 3 assumes a newer kernel:

* it reads a process's user and group ids from ``task->cred``, a structure
  added in 2.6.29. Older kernels keep ``uid``, ``gid``, ``euid`` and ``egid``
  in ``task_struct`` itself, so every plugin that lists processes fails;
* for an IPv4 socket whose ``inet_sock.daddr`` is 0 (a listening socket) it
  falls back to ``sock_common.skc_daddr``, which kernels before 2.6.33 do
  not have, and linux.sockstat stops at the first one.

This entry point bridges both and then runs Volatility unchanged; on a
kernel that has ``cred`` and ``skc_daddr`` nothing differs.

Kairon starts Linux plugins as ``python <this file> <vol arguments>``. It is
run as a script, not a module of the app, because the plugin process gets a
minimal environment: it imports nothing but Volatility.
"""
from __future__ import annotations

import sys


class _TaskCredentials:
    """What Volatility uses of ``struct cred``, read from a pre-2.6.29 task_struct."""

    def __init__(self, task) -> None:
        self._task = task

    def is_readable(self) -> bool:
        return True

    def __getattr__(self, name: str) -> int:
        return int(self._task.member(name))


def install() -> None:
    _install_task_credentials()
    _install_inet_destination()


def _install_task_credentials() -> None:
    from volatility3.framework.symbols.linux import extensions

    task_struct = extensions.task_struct
    if getattr(task_struct, "_kairon_legacy_cred", False):
        return
    original = task_struct.__getattr__

    def __getattr__(self, name):
        if name == "cred" and not self.has_member("cred") and self.has_member("uid"):
            return _TaskCredentials(self)
        return original(self, name)

    task_struct.__getattr__ = __getattr__
    task_struct._kairon_legacy_cred = True


def _install_inet_destination() -> None:
    import socket

    from volatility3.framework.symbols.linux.extensions import network

    inet_sock = network.inet_sock
    if getattr(inet_sock, "_kairon_legacy_daddr", False):
        return
    original = inet_sock.get_dst_addr

    def get_dst_addr(self):
        sk_common = getattr(self.sk, "__sk_common")
        if self.has_member("daddr") and not sk_common.has_member("skc_daddr") and sk_common.skc_family == socket.AF_INET:
            layer = self._context.layers[self.vol.layer_name]
            return socket.inet_ntop(socket.AF_INET, layer.read(self.daddr.vol.offset, 4))
        return original(self)

    inet_sock.get_dst_addr = get_dst_addr
    inet_sock._kairon_legacy_daddr = True


def main() -> None:
    install()
    from volatility3.cli import main as volatility_main

    sys.argv = ["vol", *sys.argv[1:]]
    volatility_main()


if __name__ == "__main__":
    main()
