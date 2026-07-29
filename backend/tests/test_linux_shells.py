"""Reusable login-shell classification (app.ingest.linux.shells).

Generic on purpose: covers common distro shells and non-login markers by
name, never a single hardcoded "/bin/bash" check.
"""
from app.ingest.linux.shells import classify_shell, is_login_shell


class TestClassifyShell:
    def test_common_login_shells(self):
        for shell in ("/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh", "/usr/bin/fish", "bash"):
            assert classify_shell(shell) == "login", shell

    def test_common_non_login_shells(self):
        for shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/sync", "/usr/sbin/shutdown", "/usr/sbin/halt"):
            assert classify_shell(shell) == "non_login", shell

    def test_unusual_install_path_still_recognized_by_basename(self):
        assert classify_shell("/usr/local/bin/zsh") == "login"
        assert classify_shell("/opt/custom/nologin") == "non_login"

    def test_unrecognized_shell_is_unknown_not_guessed(self):
        assert classify_shell("/usr/bin/some-custom-interpreter") == "unknown"

    def test_empty_or_missing_is_unknown(self):
        assert classify_shell("") == "unknown"
        assert classify_shell(None) == "unknown"


class TestIsLoginShell:
    def test_true_only_for_affirmatively_classified_login(self):
        assert is_login_shell("/bin/bash") is True
        assert is_login_shell("/usr/sbin/nologin") is False
        assert is_login_shell("/usr/bin/some-custom-interpreter") is False
        assert is_login_shell(None) is False
