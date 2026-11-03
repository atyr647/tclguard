# "Restart as administrator": what happens, what is tested, what is not

Controlling the operating-system firewall needs administrator rights. The GUI offers **Restart as administrator** (banner and Firewall page);
on Linux it only prints the `sudo` command, because there is no dialog to rely on.

## What it does
1. The guard stops its listeners (so the elevated copy can take the ports).
2. It starts a second copy of itself with administrator rights:
   * **Windows:** `Start-Process -Verb RunAs` (the UAC consent dialog; a standard user is asked for an administrator's name and password).
   * **macOS:** `osascript` with `do shell script ... with prompt "TclGuard needs administrator rights to control the operating-system
     firewall." with administrator privileges` (the system password dialog).
3. It waits up to 30 seconds for the new copy's control port to answer. Only then does it close its own window. If the new copy never
   starts (a crash, an antivirus), the old one takes its ports back and says so, so you are never left with no protection and no window.
4. If you say no, the message says so ("... did not get your permission, so TclGuard keeps running without administrator rights") and nothing changes.

Two details that matter because the elevated copy may run as **another account** (a standard user's UAC prompt asks for an administrator;
macOS runs it as root, whose home folder is different):
* The elevated copy always gets `--config <the file you were looking at>`, so it shows the same settings instead of starting empty.
* Files it writes inside your folder (the configuration with its control token, the ban list, certificates) are given back to the folder's
  owner (`::tg::cfg::handBack`, every 30 s and on exit). Without that, a macOS run as root would leave `~/.config/tclguard` files that your
  normal copy could no longer read.

## What is tested, and where
| | Windows | macOS |
|---|---|---|
| The command is accepted by the OS, the new copy starts **elevated** | real runner: `tests/platform/windows_test.tcl elevation` | the shell line run by root through `sudo -n`: uid 0 |
| Arguments arrive intact: spaces, apostrophes, double quotes, backslashes, `$ ` `` ` `` `&` `;` `{}` `[]`, accents | config path with spaces, an apostrophe and accents | seven awkward paths through the real AppleScript (`osascript`, without the privileges words), and as root |
| The password / consent dialog itself | **not testable**: the runner has UAC off | opens and waits for a password on a real runner (checked); a script cannot know the account password, so **not answered** |
| "I said no" is recognised | wording unit-tested (`macos_elevation_test.tcl`) | same |
| Root-written files go back to the owner | (not applicable) | `tests/handback.test` as root |

The honest gap: nobody has yet clicked through the real UAC prompt as a standard user, or typed a real password into the macOS dialog, with this
code. Everything around those two dialogs is tested on real machines; the dialogs belong to the operating systems.

## Downloaded programs: SmartScreen and Gatekeeper
The single files are not signed with a paid developer certificate (that needs an identity and a yearly fee).
* **Windows SmartScreen** may say "Windows protected your PC" for a freshly downloaded `.exe`: *More info*, then *Run anyway*. The SHA-256 of each
  file is in `releases/SHA256SUMS` (and in the signed update manifest once you have set up your signing key).
* **macOS Gatekeeper** refuses an unsigned download at first: remove the quarantine flag once with `xattr -cr tclguard-macos-arm64` (or right-click, *Open*).
  The macOS programs carry the linker's ad-hoc signature, which is what Apple-silicon requires to run at all.
