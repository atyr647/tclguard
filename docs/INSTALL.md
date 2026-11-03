# Installing and uninstalling

You downloaded one file. You never need a terminal: the app's window has an install button (it runs the same
code as `tclguard install`). This page says exactly what the installer does on each system and how to undo it
by hand.

```sh
tclguard install [--system|--user] [--service] [--no-shortcut] [--desktop] [--dir PATH] [--force] [--dry-run]
tclguard install status
tclguard uninstall [--system|--user] [--keep-data] [--dry-run]
```

* `--system` needs administrator / root; `--user` does not. Default: system when elevated, otherwise user.
* `--service` starts TclGuard automatically (details per system below).
* `--no-shortcut` skips the Start Menu / application menu entry; `--desktop` adds a desktop shortcut (Windows).
* `--dry-run` prints what would happen and changes nothing. The GUI shows the same list before asking.
* `--interactive` (used by the Windows Apps list) shows dialogs instead of printing to a terminal.
* `--force` replaces a program at the target that TclGuard did not put there (otherwise it refuses).

Installing again is safe (same bytes: nothing happens; a newer program: replaced). It only works from the
**single-file program**; a copy started with `tclsh main.tcl` has nothing to copy and the installer says so.

## The install record

Everything the installer creates is listed in an **install record** (`install.json`), and uninstall removes
**only** what is listed: next to the program on Windows (`...\TclGuard\install.json`), in
`/usr/local/share/tclguard/` (system) or `~/.local/share/tclguard/` (user) on Linux and macOS. Uninstall also
re-checks every recorded path (never `/`, a drive root, your home folder, or a system folder; folders are only
removed when empty). Settings and data (`tclguard.conf`, ban list, certificates, logs) are removed only by
uninstall *without* `--keep-data`, by fixed file name, and only inside folders called `tclguard`; anything else
you put there stays.

## Windows

| | `--user` | `--system` (administrator) |
|---|---|---|
| Program | `%LOCALAPPDATA%\Programs\TclGuard\tclguard.exe` | `%ProgramFiles%\TclGuard\tclguard.exe` |
| Start Menu | `...\Start Menu\Programs\TclGuard.lnk` (current user) | same, all users |
| Apps list (Add/Remove Programs) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\TclGuard` | `HKLM\...` |
| `--service` | Scheduled Task `TclGuard`, at sign-in | same, with highest privileges when permitted |

* The Apps-list entry has name, version, publisher, install location, icon, size, `NoModify`/`NoRepair`, and an
  uninstall command `"<exe>" uninstall --interactive` (asks, then shows the result in a dialog).
* Shortcuts are created with PowerShell (WScript.Shell COM, hidden window, `-EncodedCommand`, so spaces and
  non-ASCII user names are safe). The "Start at sign-in" task is the same Scheduled Task as *Settings > Start
  TclGuard when I sign in*.
* **Installing over a running copy:** Windows does not allow a running single-file program to be renamed or overwritten
  (it keeps its own file open), so the installation stops with a message ("... is in use ... close TclGuard (also check
  Task Manager and the TclGuard scheduled task) and run the installation again") and changes nothing. Close the running
  TclGuard, then install again. (Self-updates are different: the running program swaps itself through a helper after
  it exits, see UPDATES.md.)
* **Uninstall** removes the shortcuts, registry key, Scheduled Task, the *Windows Firewall rule created by
  TclGuard* ("TclGuard Bans", administrator only), the program (plus `.previous`/`.old` from updates), then
  the folder if empty. A running .exe cannot delete itself, so if the program you are running *is* the
  installed one, uninstall removes everything else and starts a hidden, detached PowerShell that waits for
  TclGuard to exit and then deletes the .exe, the install record and the folder (retrying for a minute; it
  never deletes recursively).
* By hand: delete the folder, the `Uninstall\TclGuard` key (`reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\TclGuard /f`),
  the shortcut, `schtasks /Delete /TN TclGuard /F`, `netsh advfirewall firewall delete rule name="TclGuard Bans"`,
  and optionally `%APPDATA%\TclGuard`.

## Linux

| | `--user` | `--system` (root) |
|---|---|---|
| Program | `~/.local/bin/tclguard` | `/usr/local/bin/tclguard` |
| Menu entry | `~/.local/share/applications/tclguard.desktop` | `/usr/share/applications/tclguard.desktop` |
| `--service` | autostart entry `~/.config/autostart/tclguard.desktop` (starts the GUI at sign-in) | systemd unit `/etc/systemd/system/tclguard.service` |

* The systemd unit is the hardened one from `packaging/tclguard.service` (a test keeps them identical) and runs
  `tclguard --headless --config /etc/tclguard/tclguard.conf`. The installer creates `/etc/tclguard/` with a
  starter `tclguard.conf` (mode 0600, a random control token, **no listeners yet**) if there is none, runs
  `systemctl daemon-reload` and `systemctl enable tclguard` when systemctl exists, and does **not** start it:
  edit the configuration, then `systemctl start tclguard`. Without systemd it only tells you the commands.
* Uninstall: `systemctl disable --now tclguard`, remove the unit, `daemon-reload`, delete the kernel table
  `nft delete table inet tclguard`, the menu entry, the program (and `.previous`), the starter config (unless
  `--keep-data`) and the state in `/var/lib/tclguard` (unless `--keep-data`).
* By hand: `sudo systemctl disable --now tclguard; sudo rm /etc/systemd/system/tclguard.service /usr/local/bin/tclguard /usr/share/applications/tclguard.desktop; sudo nft delete table inet tclguard; sudo rm -r /usr/local/share/tclguard`
  and, to drop settings, `/etc/tclguard`, `/var/lib/tclguard`, `~/.config/tclguard`.

## macOS

There is no macOS single-file program yet; running from source, the installer refuses with a message. Once one
exists: the program goes to `/usr/local/bin/tclguard` (system) or `~/.local/bin/tclguard` (user). `--service`
writes a **LaunchDaemon** `/Library/LaunchDaemons/com.tclguard.daemon.plist` (system; headless, starts at boot,
config in `/etc/tclguard`) or the per-user LaunchAgent `~/Library/LaunchAgents/com.tclguard.app.plist` (starts the
GUI at sign-in). The daemon is not started immediately: `sudo launchctl bootstrap system /Library/LaunchDaemons/com.tclguard.daemon.plist`.
There is no application bundle / menu entry. Uninstall runs `launchctl bootout`, flushes the pf anchor TclGuard
uses and removes the recorded files.

## What can go wrong

* *"cannot write ... / access denied"*: choose `--user`, or restart as administrator / use sudo.
* *"already exists and was not installed by TclGuard"*: something else is at the target; move it or `--force`.
* *"the install record is damaged"*: delete it (and follow the by-hand lists above), then install again.
* A partial install records what it did, so `tclguard uninstall` cleans up after a failure.
