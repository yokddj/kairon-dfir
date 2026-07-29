"""Reusable classification of Linux login shells.

Used anywhere Kairon needs to answer "can this account start an interactive
session" from a passwd shell field -- today that's Host User Inventory's
"login shell" semantics, but the classification is deliberately generic
(not tied to any one consumer) so it can be reused wherever a shell value
needs interpreting.
"""
from __future__ import annotations

# Interactive login shells shipped by mainstream distributions. Matched by
# basename so a full path (/bin/bash) or a bare name (bash) both work, and
# so a shell installed somewhere unusual (/usr/local/bin/zsh) still counts.
_LOGIN_SHELL_BASENAMES = {
    "sh", "bash", "dash", "ash", "zsh", "ksh", "ksh93", "mksh", "csh", "tcsh",
    "fish", "rbash", "posh", "yash", "busybox",
}

# Explicit non-interactive markers. Anything ending in "nologin" or "false"
# (regardless of path) is also treated as non-login, covering distro
# variants like /usr/sbin/nologin, /sbin/nologin, /bin/false.
_NON_LOGIN_BASENAMES = {
    "nologin", "false", "true", "sync", "halt", "shutdown", "reboot",
    "poweroff", "sulogin",
}


def classify_shell(shell: str | None) -> str:
    """Classify a passwd shell field as "login", "non_login", or "unknown".

    "unknown" is returned only for an empty/missing value or a shell this
    classifier has never seen before -- it never guesses login vs. non_login
    for something unrecognized, since that would be exactly the kind of
    single-shell special-casing this classifier exists to avoid needing.
    """
    value = (shell or "").strip()
    if not value:
        return "unknown"
    basename = value.rsplit("/", 1)[-1].lower()
    if basename in _NON_LOGIN_BASENAMES or basename.endswith("nologin"):
        return "non_login"
    if basename in _LOGIN_SHELL_BASENAMES:
        return "login"
    return "unknown"


def is_login_shell(shell: str | None) -> bool:
    """True only for a shell affirmatively classified as interactive.

    An "unknown" shell is not treated as login-capable by default -- a
    caller that wants to include unrecognized shells should check
    classify_shell() directly instead of relying on this narrower helper.
    """
    return classify_shell(shell) == "login"
