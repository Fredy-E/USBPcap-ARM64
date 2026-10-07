<h1 align="center">USBPcap-ARM64</h1>

<p align="center">
  <strong>Unofficial, community ARM64 port of <a href="https://github.com/desowin/usbpcap">USBPcap</a> — USB packet capture for Windows, native on Windows on ARM.</strong><br>
  Native build support plus driver/CLI robustness repairs. Not affiliated with or endorsed by the upstream project or desowin.org.
</p>

<p align="center">
  <a href="https://github.com/Fredy-E/USBPcap-ARM64/actions/workflows/arm64-build.yml"><img src="https://github.com/Fredy-E/USBPcap-ARM64/actions/workflows/arm64-build.yml/badge.svg?branch=master" alt="ARM64 build status"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2011%20ARM64-29354b?style=flat-square" alt="Windows 11 ARM64">
  <img src="https://img.shields.io/badge/driver-GPL--2.0-c7a366?style=flat-square" alt="Driver: GPL-2.0">
  <img src="https://img.shields.io/badge/CLI-BSD--2--Clause-737373?style=flat-square" alt="CLI: BSD-2-Clause">
  <img src="https://img.shields.io/badge/status-experimental-b3261e?style=flat-square" alt="Status: experimental">
</p>

## What this is

A focused ARM64 port of USBPcap on top of upstream `desowin/usbpcap` @ [`477b6ed`](https://github.com/desowin/usbpcap/commit/477b6ed) (2025-01-25), with full upstream history retained:

- **Native ARM64 build system** — VS 2022 (v143) with pinned modern SDK/WDK NuGet packages; unsigned, offline, build-only. Details in [build/arm64/README.md](build/arm64/README.md).
- **Driver robustness repairs** — buffer/queue/URB lifetime and completion handling, PnP and power paths, hardware-ID handling, allocation-failure paths.
- **CLI robustness repairs** — descriptor-discovery bounds, property publication, child-process rundown.
- ARM64 port modifications by Fredy-E (2026); see the git history.

> **Scope note:** build-only. This repository does not distribute signed or installable drivers, and CI never installs or loads a driver. The legacy installation/signing notes below apply to upstream builds only.

## Continuous integration

Pushes to `master` are built and verified on GitHub's hosted `windows-11-arm` runner:

1. **Strict static build contracts** — 52 tests, no compiler required.
2. **Full ARM64 Release build** — compile, link, PE checks, INF/catalog validation, and packaging.
3. CI artifacts: `arm64-logs` (per-stage logs + `validation.json`) and `arm64-offline-bundle` (offline bundle when a build completes).

## Quick start (build-only)

```sh
python build/arm64/build.py --static-only           # static contracts only
python build/arm64/build.py --configuration Release # full ARM64 build + validation
```

The solution file is `USBPcap.ARM64.sln`; see [build/arm64/README.md](build/arm64/README.md) for toolchain prerequisites and options.

## Repository layout

| Path | Contents |
| --- | --- |
| `USBPcapDriver/` | capture filter driver — GPLv2 |
| `USBPcapCMD/` | sample user-space application — BSD-2-Clause |
| `build/arm64/` | ARM64 build system, tests, and documentation |
| `.github/workflows/` | CI: static contracts + ARM64 Release build |

## Licensing

- `USBPcapDriver` — GPLv2; full text in [LICENSE-GPL-2.0.txt](LICENSE-GPL-2.0.txt)
- `USBPcapCMD` — BSD 2-Clause; full text in [LICENSE-BSD-2-Clause.txt](LICENSE-BSD-2-Clause.txt)
- ARM64 port modifications © Fredy-E (2026)

<details>
<summary><strong>Upstream documentation (retained)</strong></summary>

**End-user installer:** available at [desowin.org/usbpcap](http://desowin.org/usbpcap). The following information is intended for developers and power users.

**Legacy build instructions:**

- Download and install Windows Driver Kit 7.1.0 from Microsoft: <http://www.microsoft.com/en-us/download/details.aspx?id=11800>
- Adjust `driver_build_win7_64bit.bat` (first line of that file):
  - To change to checked build: replace `fre` with `chk`
  - To build for x86: replace `x64` with `x86`
  - To build for Windows XP: replace `WIN7` with `WXP`
- **Windows 8:** install Visual Studio 2013 Community and Windows Driver Kit 8.1 Update. From a VS2013 command prompt (in the sources directory):
  - `> Nmake2MsBuild dirs` — creates `dirs.sln`
  - `> MSBuild dirs.sln /p:Configuration="Win8 Debug"`

**Installation (legacy builds):** TESTSIGNING must be enabled to install this driver on 64-bit Windows (`Bcdedit.exe -set TESTSIGNING ON` as administrator, then reboot). Right-click `USBPcap.inf` and select Install; reboot after installing.

**Usage:** there is no capture engine DLL. Use `USBPcapCMD.exe` to select the filter instance (one per root hub) and specify the output pcap file name.

</details>
