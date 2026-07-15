import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "linux"


class TestAuthLogParser:
    @pytest.fixture
    def auth_log_content(self):
        return (FIXTURES_DIR / "auth.log").read_text()

    def test_accepted_ssh_login(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        accepted = [r for r in results if r.get("event_action") == "publickey_accepted"]
        assert len(accepted) >= 1
        entry = accepted[0]
        assert entry["username"] == "analyst"
        assert entry["auth_method"] == "publickey"
        assert entry["source_ip"] == "10.0.0.50"
        assert "RSA" in entry.get("message", "")
        assert entry["artifact_family"] == "linux_auth"
        assert entry["source_file"] == "/var/log/auth.log"

    def test_failed_ssh_password(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        failed = [r for r in results if r.get("event_action") == "password_failed"]
        assert len(failed) >= 1
        entry = failed[0]
        assert entry["username"] == "root"
        assert entry["auth_method"] == "password"
        assert entry["source_ip"] == "192.168.1.100"

    def test_sudo_command(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        sudo_cmds = [r for r in results if r.get("process") == "sudo"]
        assert len(sudo_cmds) >= 1
        entry = sudo_cmds[0]
        assert entry["username"] == "root"
        assert "systemctl" in entry.get("message", "")

    def test_su_auth(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        su_entries = [r for r in results if r.get("process") == "su"]
        assert len(su_entries) >= 1
        entry = su_entries[0]
        assert "Successful su" in entry.get("message", "")

    def test_invalid_user(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        invalid = [r for r in results if r.get("event_action") == "invalid_user"]
        assert len(invalid) >= 1
        entry = invalid[0]
        assert entry["username"] == "admin"
        assert entry["source_ip"] == "172.16.0.5"

    def test_pam_session_opened(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        opened = [r for r in results if r.get("event_action") == "session_opened"]
        assert len(opened) >= 1
        entry = opened[0]
        assert "analyst" in entry.get("message", "")

    def test_pam_session_closed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        closed = [r for r in results if r.get("event_action") == "session_closed"]
        assert len(closed) >= 1
        entry = closed[0]
        assert "analyst" in entry.get("message", "")

    def test_authentication_failure(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        failures = [r for r in results if r.get("event_action") == "auth_failure"]
        assert len(failures) >= 1
        entry = failures[0]
        assert "dbadmin" in entry.get("message", "")

    def test_all_lines_parsed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        assert len(results) == 8

    def test_timestamps_parsed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        for result in results:
            assert result["timestamp"] is not None


class TestSyslogParser:
    @pytest.fixture
    def syslog_content(self):
        return (FIXTURES_DIR / "syslog").read_text()

    def test_kernel_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        kernel = [r for r in results if r.get("process") == "kernel"]
        assert len(kernel) >= 2
        linux_entry = [r for r in kernel if "Linux version" in r.get("message", "")]
        assert len(linux_entry) >= 1
        assert "5.15.0" in linux_entry[0]["message"]

    def test_cron_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        cron = [r for r in results if r.get("process") == "CRON"]
        assert len(cron) >= 1
        entry = cron[0]
        assert "cmd" in entry.get("message", "").lower() or "CMD" in entry.get("message", "")

    def test_systemd_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        systemd = [r for r in results if r.get("process") == "systemd"]
        assert len(systemd) >= 2

    def test_all_entries_have_timestamp(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        for result in results:
            assert result["timestamp"] is not None

    def test_artifact_family_is_syslog(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        for result in results:
            assert result["artifact_family"] == "linux_syslog"

    def test_source_file_tracked(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/kern.log")
        for result in results:
            assert result["source_file"] == "/var/log/kern.log"


class TestAuditParser:
    @pytest.fixture
    def audit_content(self):
        return (FIXTURES_DIR / "audit.log").read_text()

    def test_syscall_entry(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        syscalls = [r for r in results if r.get("audit_type") == "SYSCALL"]
        assert len(syscalls) >= 2
        entry = syscalls[0]
        assert entry["success"] == "yes"
        assert entry["exe"] == "/usr/bin/sudo"

    def test_execve_with_arguments(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        execve = [r for r in results if r.get("audit_type") == "EXECVE"]
        assert len(execve) >= 1
        entry = execve[0]
        message = entry.get("message", "")
        assert "sudo" in message

    def test_user_auth(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        user_auth = [r for r in results if r.get("audit_type") == "USER_AUTH"]
        assert len(user_auth) >= 1
        entry = user_auth[0]
        assert "analyst" in entry.get("message", "")

    def test_path_entry_parsed(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        paths = [r for r in results if r.get("audit_type") == "PATH"]
        assert len(paths) >= 1
        entry = paths[0]
        assert "/etc/ssh/sshd_config" in entry.get("message", "")

    def test_audit_timestamps_parsed(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1


class TestShellHistoryParser:
    @pytest.fixture
    def bash_history_content(self):
        return (FIXTURES_DIR / ".bash_history").read_text()

    @pytest.fixture
    def zsh_history_content(self):
        return (FIXTURES_DIR / ".zsh_history").read_text()

    def test_bash_history_simple_commands(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        assert len(results) == 8
        commands = [r["command"] for r in results]
        assert "ls -la /var/log" in commands
        assert "sudo systemctl restart nginx" in commands
        assert "cat /etc/shadow" in commands

    def test_bash_history_shell_type(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        for result in results:
            assert result["shell_type"] == "bash"
            assert result["artifact_type"] == "bash_history"

    def test_zsh_history_extended_format(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        assert len(results) == 7
        commands = [r["command"] for r in results]
        assert "ls -la /var/log" in commands
        assert "kubectl get pods -n production" in commands
        assert "docker ps -a" in commands

    def test_zsh_history_timestamps(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1

    def test_zsh_history_shell_type(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        for result in results:
            assert result["shell_type"] == "zsh"
            assert result["artifact_type"] == "zsh_history"

    def test_username_inferred_from_path(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        for result in results:
            assert result["username"] == "analyst"

    def test_root_user_inferred(self):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            "ls -la /root\n",
            source_path="/root/.bash_history",
        )
        assert len(results) == 1
        assert results[0]["username"] == "root"


class TestCronParser:
    @pytest.fixture
    def crontab_content(self):
        return (FIXTURES_DIR / "root-crontab").read_text()

    def test_crontab_entries_with_schedule(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        assert len(results) >= 6

    def test_crontab_schedule_extraction(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        hourly = [r for r in results if "cron.hourly" in r.get("command", "")]
        assert len(hourly) >= 1
        assert hourly[0]["schedule"] == "17 * * * *"

    def test_crontab_user_field(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        analysts = [r for r in results if r.get("username") == "analyst"]
        assert len(analysts) >= 1
        entry = analysts[0]
        assert "health_check" in entry.get("command", "")

    def test_crontab_comments_skipped(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        messages = [r.get("message", "") for r in results]
        for msg in messages:
            assert not msg.startswith("#")
            assert "job definition" not in msg.lower()

    def test_crontab_env_vars_skipped(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        for result in results:
            assert "SHELL=" not in result.get("command", "")
            assert "PATH=" not in result.get("command", "")

    def test_crontab_artifact_family(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        for result in results:
            assert result["artifact_family"] == "linux_cron"
            assert result["artifact_type"] == "crontab"


class TestSystemdParser:
    @pytest.fixture
    def service_content(self):
        return (FIXTURES_DIR / "nginx.service").read_text()

    def test_service_unit_description(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        assert len(results) == 1
        entry = results[0]
        assert "nginx" in entry.get("description", "")
        assert entry["unit_type"] == "service"

    def test_service_execstart(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["exec_start"] is not None
        assert "/usr/sbin/nginx" in entry["exec_start"]

    def test_service_wantedby(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["wanted_by"] == "multi-user.target"

    def test_service_unit_name(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["unit_name"] == "nginx.service"
        assert entry["unit_type"] == "service"

    def test_service_execstartpre(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["exec_start_pre"] is not None
        assert "/usr/sbin/nginx" in entry["exec_start_pre"]

    def test_timer_unit_type_detected(self):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(
            "[Unit]\nDescription=Daily cleanup\n[Timer]\nOnCalendar=daily\n",
            source_path="/etc/systemd/system/cleanup.timer",
        )
        assert len(results) == 1
        assert results[0]["unit_type"] == "timer"


class TestSSHArtifactsParser:
    @pytest.fixture
    def authorized_keys_content(self):
        return (FIXTURES_DIR / "authorized_keys").read_text()

    @pytest.fixture
    def known_hosts_content(self):
        return (FIXTURES_DIR / "known_hosts").read_text()

    @pytest.fixture
    def ssh_config_content(self):
        return (FIXTURES_DIR / "ssh_config").read_text()

    def test_authorized_keys_entries(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        assert len(results) == 3

    def test_authorized_keys_key_type(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        key_types = [r["key_type"] for r in results]
        assert "ssh-rsa" in key_types
        assert "ssh-ed25519" in key_types
        assert "ecdsa-sha2-nistp256" in key_types

    def test_authorized_keys_fingerprint_present(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint
            assert "..." in fingerprint or fingerprint == "[redacted]"

    def test_authorized_keys_full_key_not_present(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint.endswith("...") or fingerprint == "[redacted]", \
                f"key_fingerprint should be truncated, got: {fingerprint}"

    def test_authorized_keys_comment(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        comments = [r["key_comment"] for r in results]
        assert "analyst@workstation" in comments

    def test_known_hosts_parsed(self, known_hosts_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            known_hosts_content,
            source_path="/home/analyst/.ssh/known_hosts",
        )
        assert len(results) == 3
        hosts = [r["host_pattern"] for r in results]
        assert "git.example.com" in hosts

    def test_known_hosts_key_redacted(self, known_hosts_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            known_hosts_content,
            source_path="/home/analyst/.ssh/known_hosts",
        )
        for result in results:
            assert result["key_fingerprint"] == "[redacted]"

    def test_ssh_config_parsed(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        assert len(results) > 0

    def test_ssh_config_host_blocks(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        host_patterns = [r.get("host_pattern") for r in results if r.get("host_pattern")]
        assert "*" in host_patterns

    def test_ssh_config_username_inferred(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        assert len(results) > 0


class TestIdentityParser:
    @pytest.fixture
    def passwd_content(self):
        return (FIXTURES_DIR / "passwd").read_text()

    @pytest.fixture
    def group_content(self):
        return (FIXTURES_DIR / "group").read_text()

    @pytest.fixture
    def shadow_content(self):
        return (FIXTURES_DIR / "shadow").read_text()

    def test_passwd_entries(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        assert len(results) >= 5

    def test_passwd_user_fields(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        usernames = [r["username"] for r in results]
        assert "root" in usernames
        assert "analyst" in usernames
        assert "nobody" in usernames

    def test_passwd_uid_gid(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        root = [r for r in results if r["username"] == "root"]
        assert len(root) == 1
        assert root[0]["uid"] == "0"
        assert root[0]["gid"] == "0"

    def test_passwd_home_and_shell(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        analyst = [r for r in results if r["username"] == "analyst"]
        assert len(analyst) == 1
        assert analyst[0]["home"] == "/home/analyst"
        assert analyst[0]["shell"] == "/bin/bash"

    def test_group_entries(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        assert len(results) >= 5

    def test_group_members(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        sudo_group = [r for r in results if r["group_name"] == "sudo"]
        assert len(sudo_group) == 1
        assert "analyst" in sudo_group[0]["members"]

    def test_group_gid(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        docker = [r for r in results if r["group_name"] == "docker"]
        assert len(docker) == 1
        assert docker[0]["gid"] == "999"

    def test_shadow_no_hashes_stored(self, shadow_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(shadow_content, source_path="/etc/shadow")
        assert len(results) == 1
        entry = results[0]
        message = entry.get("message", "")
        assert "hashes not stored" in message
        assert "root" in entry.get("username", "")


class TestSudoersParser:
    @pytest.fixture
    def sudoers_content(self):
        return (FIXTURES_DIR / "sudoers").read_text()

    def test_sudoers_rules(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        rules = [r for r in results if not r.get("is_defaults")]
        assert len(rules) >= 5

    def test_sudoers_defaults(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        defaults = [r for r in results if r.get("is_defaults")]
        assert len(defaults) >= 3

    def test_sudoers_principal(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        principals = [r["principal"] for r in results if r.get("principal")]
        assert "analyst" in principals
        assert "devops" in principals

    def test_sudoers_nopasswd_option(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        analyst_rules = [r for r in results if r.get("principal") == "analyst"]
        assert len(analyst_rules) >= 1
        assert "NOPASSWD" in analyst_rules[0].get("options", [])

    def test_sudoers_run_as(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        dbadmin_rules = [r for r in results if r.get("principal") == "dbadmin"]
        assert len(dbadmin_rules) >= 1
        assert "postgres" in dbadmin_rules[0].get("run_as", "")

    def test_sudoers_defaults_values(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        defaults = [r for r in results if r.get("is_defaults")]
        secure_path = [d for d in defaults if "secure_path" in (d.get("defaults_value") or "")]
        assert len(secure_path) >= 1


class TestPackagesParser:
    @pytest.fixture
    def dpkg_content(self):
        return (FIXTURES_DIR / "dpkg.log").read_text()

    def test_dpkg_install(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        installs = [r for r in results if r.get("action") == "install"]
        assert len(installs) >= 1
        entry = installs[0]
        assert entry["package"] == "nginx:amd64"

    def test_dpkg_upgrade(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        upgrades = [r for r in results if r.get("action") == "upgrade"]
        assert len(upgrades) >= 1
        entry = upgrades[0]
        assert "libssl" in entry.get("package", "")

    def test_dpkg_all_lines_parsed(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        assert len(results) == 10

    def test_dpkg_timestamps(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1

    def test_dpkg_package_manager_field(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        for result in results:
            assert result["package_manager"] == "dpkg"


class TestOSInfoParser:
    @pytest.fixture
    def os_release_content(self):
        return (FIXTURES_DIR / "os-release").read_text()

    @pytest.fixture
    def hostname_content(self):
        return (FIXTURES_DIR / "hostname").read_text()

    def test_os_release_name_and_version(self, os_release_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(os_release_content, source_path="/etc/os-release")
        assert len(results) == 1
        entry = results[0]
        assert entry["os_name"] == "Ubuntu"
        assert "22.04" in entry.get("os_version", "")

    def test_os_release_type(self, os_release_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(os_release_content, source_path="/etc/os-release")
        assert results[0]["artifact_type"] == "os_release"

    def test_hostname_extraction(self, hostname_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(hostname_content, source_path="/etc/hostname")
        assert len(results) == 1
        entry = results[0]
        assert entry["hostname"] == "app-server-prod-01"
        assert entry["detected_host"] == "app-server-prod-01"

    def test_hostname_artifact_type(self, hostname_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(hostname_content, source_path="/etc/hostname")
        assert results[0]["artifact_type"] == "hostname"

    def test_kernel_version_extraction(self):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(
            "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-101) Ubuntu",
            source_path="/proc/version",
        )
        assert len(results) == 1
        assert results[0]["artifact_type"] == "kernel_version"

    def test_unknown_os_info_fallback(self):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(
            "Some unknown OS info text",
            source_path="/tmp/some_os_file.txt",
        )
        assert len(results) == 1
        assert results[0]["artifact_type"] == "os_info"


class TestPlatformDetection:
    def test_linux_paths_detected_as_linux(self):
        from app.models.evidence import detect_evidence_platform
        linux_paths = [
            "/var/log/auth.log",
            "/etc/passwd",
            "/home/analyst/.bash_history",
            "/var/log/syslog",
        ]
        platform = detect_evidence_platform(paths=linux_paths)
        assert platform == "linux"

    def test_windows_paths_detected_as_windows(self):
        from app.models.evidence import detect_evidence_platform
        windows_paths = [
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        ]
        platform = detect_evidence_platform(paths=windows_paths)
        assert platform == "windows"

    def test_windows_paths_detected_as_windows_forward_slash(self):
        from app.models.evidence import detect_evidence_platform
        windows_paths = [
            "C:/Windows/System32/winevt/Logs/Security.evtx",
        ]
        platform = detect_evidence_platform(paths=windows_paths)
        assert platform == "windows"

    def test_macos_paths_detected(self):
        from app.models.evidence import detect_evidence_platform
        macos_paths = [
            "/Users/jdoe/Library/Preferences/com.apple.finder.plist",
        ]
        platform = detect_evidence_platform(paths=macos_paths)
        assert platform == "macos"

    def test_macos_direct_selection_rejected(self):
        import pytest as pt
        from fastapi import HTTPException
        from app.api.routes_evidence import _resolve_requested_platform
        with pt.raises(HTTPException) as exc_info:
            _resolve_requested_platform("macos", filename="macos_artifacts.zip")
        assert exc_info.value.status_code == 400

    def test_unknown_paths_detected_as_unknown(self):
        from app.models.evidence import detect_evidence_platform
        platform = detect_evidence_platform(paths=["/tmp/some_random.log"])
        assert platform == "unknown"

    def test_lime_memory_detected_as_memory(self):
        from app.models.evidence import detect_evidence_platform
        platform = detect_evidence_platform(paths=["memory.lime"])
        assert platform == "memory"


class TestSecretsAreNeverStored:
    @pytest.fixture
    def authorized_keys_content(self):
        return (FIXTURES_DIR / "authorized_keys").read_text()

    @pytest.fixture
    def shadow_content(self):
        return (FIXTURES_DIR / "shadow").read_text()

    def test_authorized_keys_raw_key_not_in_structured(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint.endswith("...") or fingerprint == "[redacted]", \
                f"fingerprint should be redacted, got: {fingerprint}"
            raw = result.get("raw_excerpt", "")
            assert len(raw) > len(fingerprint) or fingerprint == "[redacted]", \
                f"redacted fingerprint should be shorter than raw content"

    def test_shadow_no_hashes_in_message(self, shadow_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(shadow_content, source_path="/etc/shadow")
        entry = results[0]
        assert entry["artifact_type"] == "shadow"
        message = entry.get("message", "")
        assert "6$" not in message
        assert "hashes not stored" in entry.get("message", "")
        username_field = entry.get("username", "")
        assert "$" not in username_field
