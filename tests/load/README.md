# Load and flood tests

* `run_flood.py` - the sustained flood test (legitimate-visitor probe + attackers + resource sampling). Works on Linux, Windows and macOS.
* `run_flood_netns.sh` - the same test over a real kernel network path (two network namespaces, Linux, root), with `--fw none|bans|harden` and `--syn`.
* `tgload/` - the Go load generators (`cd tgload && go build -o ../tgload-bin .`; Windows: `tgload-bin.exe`).
* Results and what they mean: [../../docs/LOAD.md](../../docs/LOAD.md). CI: `.github/workflows/flood.yml`.

```sh
# loopback, Linux/macOS
TG_CMD=releases/tclguard-linux-x86_64 python3 tests/load/run_flood.py [--quick] [--soak SECONDS] [--fw bans]
# real network path with the kernel firewall (Linux, root)
sudo TG_CMD=releases/tclguard-linux-x86_64 tests/load/run_flood_netns.sh --fw bans --syn
```
