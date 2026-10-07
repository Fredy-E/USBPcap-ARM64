# Native ARM64 build-only USBPcap

This configuration builds the **current upstream WDM capture code**, not the old
experimental fork's C sources. The initial upstream base is
`477b6edcbd7e99a47f77afc0c4168a9ebee603bb` (2025-02-09). All 12 driver C translation
units, all 8 CMD C translation units, and both resources match their legacy
`SOURCES` manifests. Existing legacy build/install/sign scripts are not called.

**No driver installation/loading, certificate import, boot/security changes,
reboot, host-application configuration changes, or device/vehicle commands are performed.**
The installed x64 USBPcap executable and driver are not read or replaced.

## Dependencies (install/restore separately)

- VS 2022 Build Tools, v143 C++ headers/libraries and native ARM64 target compiler.
  A native ARM64 host or an x64 host compiler running under Windows-on-Arm
  emulation is supported; an x64 **kernel target** is not.
- Python 3.9+ (standard library only), Git, and full desktop MSBuild.
- These three NuGet packages, **exactly 10.0.26100.3323**, extracted/restored as
  `packages/<package-id>.10.0.26100.3323/` in the repository:
  `Microsoft.Windows.WDK.ARM64`, `Microsoft.Windows.SDK.CPP`, and
  `Microsoft.Windows.SDK.CPP.arm64`.
- Package manifest: `build/arm64/packages.config`. Package revision `.3323`
  contains SDK/WDK directories named `10.0.26100.0`; they are not mismatched kits.

If dependency acquisition is separately approved, the external restorer can use:

```text
nuget.exe restore build/arm64/packages.config -PackagesDirectory packages -Source <approved-local-feed-or-nuget-source> -NonInteractive
```

The build script does **not** download, install, or restore anything.

## Commands (from the repository root)

```text
python build/arm64/build.py --static-only
python build/arm64/build.py --check-only
python build/arm64/build.py --configuration Release
python build/arm64/build.py --configuration Debug
```

Use `--vs-root`, `--msbuild`, `--host ARM64|x64`, `--packages`, and
`--vc-tools-version <installed-version>` to select/pin an alternate installation.
The default MSBuild path is:

```text
C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/MSBuild/Current/Bin/arm64/MSBuild.exe
```

For **compile/link only**, without offline validation/package creation:

```text
MSBuild.exe USBPcap.ARM64.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=ARM64 /p:SignMode=Off
```

Both projects enforce ARM64, pinned kit version, and signing/deployment disabled
before building. The wrapper checks headers, target libraries, compilers, the
ARM64 v143 platform props, and offline validation tools before invoking MSBuild.
Library checks cover every explicit kernel/SDK project dependency, including
`user32`, `gdi32`, `ole32`, `oleaut32`, and `uuid`, plus inherited v143 desktop
libraries (`winspool`, `odbc32`, `odbccp32`). CMD's selected static runtime is checked:
Release requires `libcmt.lib`, `libvcruntime.lib`, and `libucrt.lib`; Debug requires
`libcmtd.lib`, `libvcruntimed.lib`, and `libucrtd.lib`. Both require `oldnames.lib`.
All are **ARM64 target** libraries regardless of compiler host. The driver excludes
default CRT libraries and retains its explicit kernel/ARM64 runtime dependencies.
Missing dependencies stop the build with their exact paths. It also verifies
MSBuild and the compiler actually launch rather than trusting installer metadata.

## Project design

The projects use v143 plus explicit WDK kernel switches/includes/libraries,
so they do not require a globally installed WDK Visual Studio extension or a
`WindowsKernelModeDriver10.0` platform-toolset installation. The driver's
MSBuild `ConfigurationType=Application` is the **v143 executable-link pipeline**;
its output is `.sys`, `/DRIVER /kernel`, Native subsystem, native ARM64 machine,
`DriverType=WDM`, and `DriverTargetPlatform=Desktop`. It is not a user-mode driver
or a KMDF conversion. `GsDriverEntry` and `bufferoverflowfastfailk.lib` preserve the
modern WDM `/GS` startup wrapper around the upstream `DriverEntry`; no
`FxDriverEntry`/WDF library is added. Original Wdm/Wdmsec/Ntstrsafe/Ntoskrnl/USBD
libraries are retained; modern kernel support and ARM64 runtime libraries are
explicit. Default user-mode CRT libraries are excluded from the driver.

`POOL_NX_OPTIN=1` and upstream `ExInitializeDriverRuntime(DrvRtPoolNxOptIn)` remain
in place. Both projects force-include compile-time wire/IOCTL structure-size and
offset assertions. These assertions are only exercised by a real C compilation,
not by the Python static tests.

The CMD keeps upstream `WinMain`/parent-console behavior (Windows subsystem),
ANSI API usage, and original library dependencies. Its build-only manifest is
real ARM64 XML with `asInvoker`, separate from the macro-based legacy manifest.
CMD statically links the MSVC runtime for a self-contained offline executable.

## Validation stages and outputs

The wrapper uses `/t:Rebuild` to avoid packaging stale binaries. Outputs live
only in `artifacts/`, with separate Debug/Release and per-project intermediates.
Logs, build binlog, source-file SHA-256 snapshot, toolchain selection, exact
commands/exit codes, and stage outcomes are stored in
`artifacts/logs/ARM64/<configuration>/validation.json`.
The report is created **before static tests or prerequisite discovery**, including
for `--static-only` and `--check-only`. Each attempted stage is persisted before
execution and after completion/failure. Outcomes use `passed`, `failed`, or
`not_run`; `attempted` distinguishes an in-progress attempt from an untouched
stage. Exceptions include their type/message and current stage, while completed
command output, exit codes, logs, and prior results remain recorded. Partial PE
metadata and the failing image are retained. Source metadata/invariance, tool
launches, staging, and validation-policy enforcement have separate stage entries.
Report writes use a temporary file plus replacement; an unwritable report path
is an explicit fatal error, not a promise that persistence succeeded.

1. Static contract tests: XML/manifest parsing, exact `SOURCES` agreement,
   libraries, platform, WDM/GS entry, ABI-header wiring, pinned dependencies,
   solution mapping, and build-only guards.
2. Dependency existence and executable-launch checks.
3. Compile/link, including compiler ABI assertions.
4. Offline PE inspection: valid PE32+ headers, section/file alignment and bounded,
   nonoverlapping section ranges within the file/image; `0xAA64`, Native driver/GUI
   CMD subsystems, and an instruction-aligned entrypoint in file-backed executable
   content (not raw padding or zero-fill). The driver requires page-aligned sections;
   user-mode-only DLL characteristics are not imposed on it. Import descriptors
   must terminate within their declared directory size, and module names must
   terminate within mapped section content. No CLR, no embedded certificate, NX
   compatibility, no writable-executable sections, and the driver import-module
   allowlist remain mandatory. This is **not** a complete loader verifier or HVCI proof.
5. INF syntax (`InfVerif /v`) and desktop signability (`InfVerif /v /h`).
6. `Inf2Cat /os:10_GE_ARM64` (Windows 11 24H2) creates an **unsigned** catalog
   when validation permits. No signing tool or certificate is invoked.
7. ARM64 universal-DDI ApiValidator diagnostic, explicitly informational because
   this is a **Desktop** WDM/class-filter package, not a Universal/DCH claim.
   `-ApiExtractorExePath:` receives the **directory containing `AitStatic.exe`**,
   as specified by the pinned WDK's `1033/ApiValidator.xml`, not the executable path.
8. Offline ZIP with fixed timestamps, stable ordering, SHA256SUMS, rebuilt SYS,
   CMD, PDBs, ARM64 INF, optional generated unsigned CAT, license notices,
   `OFFLINE-ONLY.txt`, and validation report. ZIP members, exact staged content,
   CRC integrity, and manifest hashes are checked.

Packaging is a two-pass transaction. A temporary candidate ZIP is written and
verified first. Its successful outcome is then embedded in `validation.json` as
`offline_package.status=passed`, with the precise
`phase=payload_and_candidate_verified`, `status_scope`, and
`candidate_archive_verification`. This describes **completed staging/candidate
verification**, not an unperformed check of the final ZIP containing that report.
The updated manifest and `SHA256SUMS` are embedded in a second ZIP, which is
verified again before replacing the published ZIP. Final verification,
`phase=completed`, `published=true`, and the final ZIP SHA-256 are recorded **only
in the external report**, avoiding circular ZIP/manifest hashing. Writing or
verification exceptions mark the external package stage failed, preserve prior
results, and do not publish the temporary ZIP or replace a previous successful
ZIP. An older ZIP may remain after a failed run; use the current external report
and its hash rather than treating file existence as a successful build.

The default `--validation-policy strict` refuses a new ZIP if INF syntax,
desktop signability, or catalog generation fails. To retain a research bundle
**after actually running all those checks**, explicitly use:

```text
python build/arm64/build.py --configuration Release --validation-policy record
```

`record` never skips validations, ignores compile/PE failures, signs, or deploys.
It includes the actual validation failures in the bundle and labels it
**unqualified for installation**. Even a strict-mode bundle is not production
signed, trusted, hardware tested, or approved for loading. Process-launch,
internal validation, missing-output, and filesystem exceptions still stop either
policy; `record` permits recorded nonzero INF/catalog command exits, not skipped
or incomplete execution.

The stdlib regression suite can also be run directly without creating repository
build artifacts:

```text
python build/arm64/test_build.py
```

Its synthetic prerequisite files and mocked external commands exercise both
configurations, failure persistence, strict/record boundaries, package-stage
reporting, archive verification failures, ZIP/hash consistency, and the actual
ApiValidator command's extractor-directory argument. Constructed PE32+ byte fixtures
exercise the **real parser and inspection gates**, including valid Native/GUI
images, raw alignment padding, zero-filled sections and overlays, plus malformed
section ranges, unmapped/non-executable entrypoints, invalid alignment, out-of-range
import names and missing descriptor terminators that could hide forbidden modules.
Compile and actual PE failures remain fatal under **both** policies. These temporary
fixtures are **not** compiled binaries, Windows-loadability proof or real WDK
validation evidence. No compiler, dependency installation, driver operation, or
third-party Python package is needed; set `TMPDIR` to select the test scratch directory.

No implicit WDK MSBuild INF/API tasks are run in these v143 projects; all offline
validation commands are explicit in the wrapper. Direct MSBuild compile-only
therefore means **INF/API/catalog validation NOT RUN**. Driver loading, Driver
Verifier, HLK, Secure-Boot/HVCI trust qualification, and actual capture tests are
always recorded as not performed or are outside this build-only scope.

## Reproducibility and remaining risks

Kit dependencies and target configuration are fixed. Compiler version can be
pinned explicitly and is always recorded. Link `/Brepro`, fixed INF DriverVer
`02/09/2025,1.5.4.0` (upstream base date/version), sorted ZIP entries, and fixed ZIP
timestamps remove several time-dependent inputs. This is a reproducible build
**configuration**, not a claim of byte-identical PDBs/ZIPs across machines, source
paths, different MSVC versions, or logs. Reports intentionally retain actual paths
and validation results. No successful compilation is claimed until compiler and
linker output are available.

- The ARM64 INX preserves upstream's legacy USB class UpperFilters registration
  and uninstall semantics. It is **not silently rewritten into a primitive,
  DCH, or isolated INF**. Modern `/h` or catalog checks may reject it; diagnostics
  must be reviewed before any separately authorized deployment design.
- Upstream legacy nonpaged-pool allocation APIs may generate deprecation warnings.
  NX opt-in and static ABI checks do not prove ARM64 alignment, synchronization,
  IRP lifetime, cancellation, or hardware capture correctness.
- Upstream driver version resource still identifies FILETYPE as VFT_APP; it is
  preserved unchanged here and should be reviewed separately for distribution.
- Building does not audit or repair all pre-existing source-level warning sites.
  Warning-as-error is intentionally false so warning logs remain evidence rather
  than being hidden by broad suppression. Production qualification remains open.
- Public older test-signed ARM64 binaries, bundled test keys/certificates,
  legacy installers, and capture workflows are excluded from the offline bundle.
- Redistribution of GPL driver binaries requires source/license compliance;
  the exact source/build inputs are recorded, but the offline ZIP is not an
  end-user installer or a complete production source-distribution workflow.

References: Microsoft [WDK NuGet](https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget),
[InfVerif CLI](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/running-infverif-from-the-command-line),
and the historical [upstream ARM64 project PR](https://github.com/desowin/usbpcap/pull/134).
