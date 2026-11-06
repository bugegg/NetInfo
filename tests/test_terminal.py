"""SSH / Telnet from the right-click menu, opened in the system terminal."""

import pytest
from PyQt6.QtWidgets import QInputDialog

from NetInfoView.ui import terminal
from test_main_window import window, qapp, _entries_with_statuses  # noqa: F401


def test_ssh_command_allows_legacy_algorithms_for_old_network_gear(monkeypatch):
    monkeypatch.setattr(terminal, "IS_WINDOWS", False)
    command = terminal.ssh_command("10.0.0.1", "admin")
    assert command[0] == "ssh" and command[-1] == "admin@10.0.0.1"
    assert "HostKeyAlgorithms=+ssh-rsa" in command
    assert terminal.ssh_command("10.0.0.1")[-1] == "10.0.0.1"


@pytest.mark.parametrize("ip", ["10.0.0.1; rm -rf ~", "$(id)", "host name"])
def test_only_addresses_reach_the_terminal(ip):
    with pytest.raises(ValueError):
        terminal.ssh_command(ip)
    with pytest.raises(ValueError):
        terminal.telnet_command(ip)


@pytest.mark.parametrize("name", ["a b", "x;y", "$(id)", "'q'", ""])
def test_odd_user_names_are_refused(name):
    assert not terminal.valid_username(name)


def test_macos_script_runs_the_command_and_explains_a_missing_telnet():
    script = terminal.macos_script(["telnet", "10.0.0.1"])
    assert script.startswith("#!/bin/zsh -l\n")
    assert "\n  telnet 10.0.0.1\n" in script
    assert "spawn -noecho {telnet} {10.0.0.1};" in script
    assert "brew install telnet" in script


def test_delete_key_is_sent_as_backspace():
    wrapped = terminal.backspace_wrapped(["telnet", "10.0.0.1"])
    assert wrapped[:2] == ["/usr/bin/expect", "-c"]
    assert 'interact "\\177" {send "\\010"}' in wrapped[2]
    assert "exit [lindex $result 3]" in wrapped[2]  # keeps telnet's exit status


def test_macos_script_closes_its_window_when_the_session_ends():
    script = terminal.macos_script(["telnet", "10.0.0.1"])
    assert "exec " not in script  # the script must outlive the session
    assert 'close (every window whose tty of selected tab is' in script
    assert "&!\n" in script  # detached, so Terminal asks nothing on close
    assert "Press any key to close." in script  # a quick failure stays readable


def test_menu_actions_open_the_selected_host(window, monkeypatch):
    monkeypatch.setattr(terminal, "IS_WINDOWS", False)
    opened = []
    monkeypatch.setattr(terminal, "open_in_terminal", opened.append)
    monkeypatch.setattr(window.settings, "save", lambda: None)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("admin", True))
    entries = _entries_with_statuses(window, "10.0.0.7")
    entries[0].ip_address = "10.0.0.7"
    window._table.selectRow(0)

    window.action_telnet.trigger()
    window.action_ssh.trigger()
    assert opened[0] == terminal.telnet_command("10.0.0.7")
    assert opened[0][-1] == "10.0.0.7"
    assert opened[1][-1] == "admin@10.0.0.7"
    assert window.settings.ssh_username == "admin"
    assert window.action_ssh in window._table.actions()


def test_telnet_skips_automatic_login_on_macos(monkeypatch):
    """Else macOS telnet tries Kerberos and prints an error at the prompt."""
    monkeypatch.setattr(terminal, "IS_WINDOWS", False)
    assert terminal.telnet_command("10.0.0.1") == ["telnet", "-K", "10.0.0.1"]


def test_windows_uses_the_bundled_plink_for_ssh_and_telnet(monkeypatch, tmp_path):
    plink = tmp_path / "putty" / "plink.exe"
    plink.parent.mkdir()
    plink.write_bytes(b"")
    monkeypatch.setattr(terminal, "IS_WINDOWS", True)
    monkeypatch.setattr(terminal, "BUNDLED_PLINK", plink)
    session = ["-load", terminal.PUTTY_SESSION]
    assert terminal.telnet_command("10.0.0.1") == [str(plink), *session, "-telnet", "10.0.0.1"]
    assert terminal.ssh_command("10.0.0.1", "admin") == [
        str(plink), *session, "-ssh", "-l", "admin", "10.0.0.1"]
    assert terminal.ssh_command("10.0.0.1")[-2:] == ["-ssh", "10.0.0.1"]  # plink asks the name


def test_plink_falls_back_to_one_on_the_path(monkeypatch, tmp_path):
    monkeypatch.setattr(terminal, "BUNDLED_PLINK", tmp_path / "missing.exe")
    monkeypatch.setattr(terminal.shutil, "which", lambda name: r"C:\PuTTY\plink.exe")
    assert terminal.plink_path() == r"C:\PuTTY\plink.exe"


def test_putty_session_allows_old_algorithms_without_asking():
    """Old Cisco/HPE gear: dh-group1-sha1, 3des, ssh-rsa/dsa sit above
    PuTTY's WARN line, so plink connects without a "below threshold" prompt."""
    settings = terminal.PUTTY_SETTINGS
    for name, old in (("KEX", "dh-group1-sha1"), ("Cipher", "3des"), ("HostKey", "dsa")):
        order = settings[name].split(",")
        assert order.index(old) < order.index("WARN"), name
    assert settings["KEX"].split(",")[-1] == "WARN"


def test_windows_script_hints_closes_and_keeps_quick_failures_readable():
    script = terminal.windows_script([r"C:\Program Files\NetInfoView\plink.exe", "-telnet", "10.0.0.1"])
    assert "plink is not installed. Install PuTTY" in script
    assert r"& 'C:\Program Files\NetInfoView\plink.exe' '-telnet' '10.0.0.1';" in script
    assert "Press any key to close." in script
    # A DOMAIN\user name and a quote can't break out of PowerShell's quoting.
    assert "'CORP\\bob'" in terminal.windows_script(["plink", "-l", "CORP\\bob", "10.0.0.1"])
    assert terminal._ps_quote("it's") == "'it''s'"


@pytest.mark.skipif(not terminal.IS_WINDOWS, reason="writes the Windows registry")
def test_putty_session_is_saved_to_the_registry():
    import winreg
    terminal.save_putty_session()
    path = rf"Software\SimonTatham\PuTTY\Sessions\{terminal.PUTTY_SESSION}"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        assert winreg.QueryValueEx(key, "KEX")[0] == terminal.PUTTY_SETTINGS["KEX"]


@pytest.mark.skipif(not terminal.IS_WINDOWS, reason="runs Windows PowerShell")
def test_windows_script_runs_in_powershell():
    import subprocess
    script = terminal.windows_script(["cmd", "/c", "echo", "hello from cmd"])
    done = subprocess.run(["powershell", "-NoLogo", "-NoProfile", "-Command", script],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "hello from cmd" in done.stdout
    assert "Press any key" not in done.stdout  # succeeded: closes straight away
