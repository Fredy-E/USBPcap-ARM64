"""Build native ARM64 binaries and produce an UNSIGNED OFFLINE research bundle.

No installers, device access, signing, certificate/boot changes, or driver loading.
Requires Python 3.9+ stdlib. Dependencies are restored/installed separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_VERSION = '10.0.26100.3323'
KIT_VERSION = '10.0.26100.0'
PINNED_COMMIT = '477b6edcbd7e99a47f77afc0c4168a9ebee603bb'
PACKAGES = ('Microsoft.Windows.WDK.ARM64', 'Microsoft.Windows.SDK.CPP', 'Microsoft.Windows.SDK.CPP.arm64')
DEFAULT_VS = Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools')


def pe_metadata(data):
    """Validate PE32+ layout and read build-gate metadata without executing it.

    RVA reads must be file-backed section content, not padding, zero-fill,
    another section, or an overlay. This is not a Windows loader/PE verifier.
    """
    def check(condition, message):
        if not condition:
            raise ValueError(message)

    def power_of_two(value):
        return value > 0 and value & (value - 1) == 0

    def aligned(value, alignment):
        return (value + alignment - 1) // alignment * alignment

    check(len(data) >= 64 and data[:2] == b'MZ', 'Not a PE image')
    off = struct.unpack_from('<I', data, 0x3C)[0]
    check(off >= 64 and off + 24 <= len(data) and data[off:off + 4] == b'PE\0\0',
          'Invalid PE header')
    machine, count = struct.unpack_from('<HH', data, off + 4)
    opt_size, characteristics = struct.unpack_from('<HH', data, off + 20)
    check(1 <= count <= 96 and characteristics & 0x2, 'Invalid executable/section count')
    opt = off + 24
    check(opt_size >= 112 and opt + opt_size <= len(data) and
          struct.unpack_from('<H', data, opt)[0] == 0x20B,
          'Expected complete PE32+ optional header')
    directory_count = struct.unpack_from('<I', data, opt + 108)[0]
    check(directory_count <= (opt_size - 112) // 8, 'Data directories exceed optional header')
    section_alignment, file_alignment = struct.unpack_from('<II', data, opt + 32)
    check(power_of_two(section_alignment) and power_of_two(file_alignment) and
          section_alignment >= file_alignment, 'Invalid section/file alignment')
    # Low-alignment images are legal in general PE parsing, but not this kernel
    # target (checked separately). Do not impose user-mode DLL flags on drivers.
    check((section_alignment < 0x1000 and file_alignment == section_alignment) or
          (section_alignment >= 0x1000 and 0x200 <= file_alignment <= 0x10000),
          'Invalid file alignment for section alignment')
    image_size, headers_size = struct.unpack_from('<II', data, opt + 56)
    section_start = opt + opt_size
    check(section_start + count * 40 <= headers_size <= len(data) and
          headers_size % file_alignment == 0, 'Invalid headers size/section table')
    check(image_size > 0 and image_size % section_alignment == 0 and
          image_size >= aligned(headers_size, section_alignment), 'Invalid image size')
    sections, raw_ranges = [], []
    previous_virtual_end = aligned(headers_size, section_alignment)
    for i in range(count):
        pos = section_start + i * 40
        name = data[pos:pos + 8].split(b'\0')[0].decode('ascii', errors='replace')
        virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, pos + 8)
        flags = struct.unpack_from('<I', data, pos + 36)[0]
        span = max(virtual_size, raw_size)
        virtual_end = aligned(rva + span, section_alignment)
        check(span > 0 and rva % section_alignment == 0 and
              rva >= previous_virtual_end and virtual_end <= image_size,
              'Invalid section virtual range/alignment: ' + name)
        previous_virtual_end = virtual_end
        if raw_size:
            check(raw >= headers_size and raw % file_alignment == 0 and
                  raw_size % file_alignment == 0 and raw + raw_size <= len(data),
                  'Invalid section raw range/alignment: ' + name)
            check(all(raw + raw_size <= start or raw >= end for start, end in raw_ranges),
                  'Overlapping section raw ranges: ' + name)
            if section_alignment < 0x1000:
                check(raw == rva, 'Low-alignment section file offset must equal RVA')
            raw_ranges.append((raw, raw + raw_size))
        sections.append({'name': name, 'rva': rva, 'virtual_size': virtual_size,
                         'raw': raw, 'raw_size': raw_size, 'flags': flags})

    def rva_range(rva, size=1):
        check(rva > 0 and size > 0 and rva + size <= image_size, 'Invalid RVA range')
        for section in sections:
            # MSVC can emit raw alignment padding and zero-filled .bss. Neither
            # is initialized content; VirtualSize==0 uses the raw extent.
            content_size = min(section['raw_size'], section['virtual_size'] or section['raw_size'])
            delta = rva - section['rva']
            if 0 <= delta and delta + size <= content_size:
                start = section['raw'] + delta
                return start, section['raw'] + content_size, section
        raise ValueError('Unmapped or non-file-backed RVA range')

    entrypoint = struct.unpack_from('<I', data, opt + 16)[0]
    if machine == 0xAA64:
        check(entrypoint % 4 == 0, 'ARM64 entrypoint is not instruction-aligned')
    _, _, entry_section = rva_range(entrypoint, 4 if machine == 0xAA64 else 1)
    check(entry_section['flags'] & 0x20000000, 'Entrypoint is not executable section content')

    def directory(index):
        if index >= directory_count:
            return 0, 0
        address, size = struct.unpack_from('<II', data, opt + 112 + index * 8)
        check(bool(address) == bool(size), 'Incomplete data directory: ' + str(index))
        return address, size

    imports = []
    import_rva, import_size = directory(1)
    if import_rva:
        base, _, _ = rva_range(import_rva, import_size)
        terminated = False
        for idx in range(import_size // 20):
            desc = struct.unpack_from('<IIIII', data, base + 20 * idx)
            if not any(desc):
                terminated = True
                break
            start, limit, _ = rva_range(desc[3])
            end = data.find(b'\0', start, limit)
            check(end > start, 'Empty or unterminated import name within section content')
            imports.append(data[start:end].decode('ascii').lower())
        check(terminated, 'Import descriptor table lacks terminator within declared size')
    # The security directory uses a FILE OFFSET, not an RVA.
    security_offset, security_size = directory(4)
    if security_size:
        check(security_offset % 8 == 0 and security_offset + security_size <= len(data),
              'Invalid certificate file range')
    clr_rva, clr_size = directory(14)
    if clr_size:
        rva_range(clr_rva, clr_size)
    return {'machine': hex(machine), 'subsystem': struct.unpack_from('<H', data, opt + 68)[0],
            'dll_characteristics': hex(struct.unpack_from('<H', data, opt + 70)[0]),
            'entrypoint_rva': entrypoint, 'section_alignment': section_alignment,
            'file_alignment': file_alignment, 'image_size': image_size, 'headers_size': headers_size,
            'security_size': security_size, 'security_offset': security_offset,
            'clr_size': clr_size, 'clr_rva': clr_rva, 'imports': imports,
            'sections': sections}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def source_snapshot():
    paths = [ROOT / 'USBPcap.ARM64.sln']
    for folder in ('USBPcapDriver', 'USBPcapCMD', 'build/arm64'):
        paths.extend(p for p in (ROOT / folder).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.user'))
    return {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


def run(command, log=None, env=None):
    print('>', subprocess.list2cmdline([str(x) for x in command]), flush=True)
    completed = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               encoding='utf-8', errors='replace')
    print(completed.stdout, flush=True)
    result = {'command': [str(x) for x in command], 'exit_code': completed.returncode,
              'status': 'passed' if completed.returncode == 0 else 'failed',
              'log': str(log.relative_to(ROOT)) if log else None, 'output': completed.stdout}
    if log:
        try:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(completed.stdout, encoding='utf-8')
        except OSError as error:
            # Preserve the completed invocation/output even if writing its log fails.
            error.command_result = result
            raise
    return result


def dependencies(args):
    vs = args.vs_root.resolve()
    msbuild = args.msbuild or vs / 'MSBuild/Current/Bin/arm64/MSBuild.exe'
    version_file = vs / 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
    vc_version = args.vc_tools_version
    if not vc_version and version_file.is_file():
        vc_version = version_file.read_text(encoding='utf-8-sig').strip()
    vc = vs / 'VC/Tools/MSVC' / (vc_version or 'MISSING')
    host = args.host
    if host == 'auto':
        host = next((h for h in ('ARM64', 'x64') if (vc / ('bin/Host' + h) / 'arm64/cl.exe').is_file()), 'ARM64')
    compiler_dir = vc / ('bin/Host' + host) / 'arm64'
    package_dirs = {p: args.packages / (p + '.' + PACKAGE_VERSION) for p in PACKAGES}
    wdk, sdk, libs = [package_dirs[p] / 'c' for p in PACKAGES]
    checks = [msbuild, compiler_dir / 'cl.exe', compiler_dir / 'link.exe',
              vc / 'include/vcruntime.h',
              vs / 'MSBuild/Microsoft/VC/v170/Platforms/ARM64/PlatformToolsets/v143/Toolset.props',
              wdk / ('Include/' + KIT_VERSION + '/km/ntddk.h'),
              sdk / ('Include/' + KIT_VERSION + '/shared/usb.h'),
              sdk / ('Include/' + KIT_VERSION + '/um/Windows.h'),
              sdk / ('Include/' + KIT_VERSION + '/ucrt/stdio.h')]
    checks += [wdk / ('Lib/' + KIT_VERSION + '/km/ARM64/' + lib) for lib in
               ('wdm.lib', 'wdmsec.lib', 'ntstrsafe.lib', 'ntoskrnl.lib', 'usbd.lib',
                'hal.lib', 'wmilib.lib', 'bufferoverflowfastfailk.lib')]
    checks += [libs / ('um/arm64/' + lib) for lib in
               ('arm64rt.lib', 'hid.lib', 'setupapi.lib', 'comdlg32.lib', 'advapi32.lib',
                'cfgmgr32.lib', 'shell32.lib', 'shlwapi.lib', 'kernel32.lib', 'user32.lib',
                'gdi32.lib', 'ole32.lib', 'oleaut32.lib', 'uuid.lib',
                # Inherited v143 desktop default AdditionalDependencies.
                'winspool.lib', 'odbc32.lib', 'odbccp32.lib')]
    # CMD /MT or /MTd: static CRT, vcruntime, UCRT and legacy-name support.
    # The driver uses /Zl + /NODEFAULTLIB and only its explicit kernel libraries.
    suffix = 'd' if args.configuration == 'Debug' else ''
    checks += [vc / ('lib/arm64/' + lib) for lib in
               ('libcmt' + suffix + '.lib', 'libvcruntime' + suffix + '.lib', 'oldnames.lib')]
    checks += [libs / ('ucrt/arm64/libucrt' + suffix + '.lib')]
    for p in PACKAGES:
        prop = {'Microsoft.Windows.WDK.ARM64': 'build/native/Microsoft.Windows.WDK.arm64.props',
                'Microsoft.Windows.SDK.CPP': 'build/native/Microsoft.Windows.SDK.cpp.props',
                'Microsoft.Windows.SDK.CPP.arm64': 'build/native/Microsoft.Windows.SDK.cpp.arm64.props'}[p]
        checks.append(package_dirs[p] / prop)
    # Host tools follow compiler host; target libraries/imports ALWAYS follow ARM64.
    sdk_host = 'arm64' if host == 'ARM64' else 'x64'
    rc = sdk / ('bin/' + KIT_VERSION + '/' + sdk_host + '/rc.exe')
    mt = rc.with_name('mt.exe')
    infverif = wdk / ('tools/' + KIT_VERSION + '/ARM64/infverif.exe')
    apivalidator = wdk / ('bin/' + KIT_VERSION + '/' + sdk_host + '/apivalidator.exe')
    inf2cat = wdk / ('bin/' + KIT_VERSION + '/x86/Inf2Cat.exe')
    api_xml = wdk / ('build/' + KIT_VERSION + '/universalDDIs/arm64/UniversalDDIs.xml')
    whitelist = api_xml.with_name('ModuleWhitelist.xml')
    aitstatic = apivalidator.with_name('AitStatic.exe')
    checks += [rc, mt, infverif, inf2cat, apivalidator, api_xml, whitelist, aitstatic]
    missing = [str(p) for p in checks if not p.is_file()]
    require(not missing, 'Missing build/validation prerequisites (install/restore separately):\n  ' + '\n  '.join(missing))
    return {'msbuild': msbuild, 'vc_version': vc_version, 'host': host, 'compiler_dir': compiler_dir,
            'rc_dir': rc.parent, 'infverif': infverif, 'apivalidator': apivalidator,
            'inf2cat': inf2cat, 'api_xml': api_xml, 'whitelist': whitelist, 'aitstatic': aitstatic}


def archive_package(stage, path):
    """Fixed zip timestamps and stable ordering; never bundles private keys/certs."""
    allowed = {'USBPcap.sys', 'USBPcapCMD.exe', 'USBPcap.inf', 'USBPcaparm64.cat', 'usbpcaparm64.cat',
               'USBPcap.pdb', 'USBPcapCMD.pdb', 'GPL-2.0.txt', 'BSD-2-Clause.txt',
               'getopt-NOTICE.txt', 'OFFLINE-ONLY.txt', 'validation.json', 'SHA256SUMS'}
    names = [p.name.casefold() for p in stage.iterdir()]
    require(len(names) == len(set(names)), 'Case-colliding offline bundle members')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for file in sorted(stage.iterdir()):
            require(file.is_file() and file.name in allowed, 'Unexpected offline bundle member: ' + str(file))
            info = zipfile.ZipInfo(file.name, (2025, 2, 9, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, file.read_bytes(), compresslevel=9)
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None, 'Offline ZIP integrity check failed')
        members = {p.name for p in stage.iterdir()}
        require(len(z.namelist()) == len(members) and set(z.namelist()) == members,
                'Offline ZIP member mismatch')
        for file in stage.iterdir():
            require(z.read(file.name) == file.read_bytes(), 'Offline ZIP content mismatch: ' + file.name)
        if 'SHA256SUMS' in members:
            lines = z.read('SHA256SUMS').decode('ascii').splitlines()
            sums = dict(line.split('  ', 1)[::-1] for line in lines)
            require(len(sums) == len(lines) and set(sums) == members - {'SHA256SUMS'},
                    'Offline ZIP SHA256SUMS member mismatch')
            for name, digest in sums.items():
                require(digest == hashlib.sha256(z.read(name)).hexdigest(),
                        'Offline ZIP SHA256SUMS mismatch: ' + name)


class ValidationReport:
    """Persist each attempted stage, including exceptions, before proceeding."""

    def __init__(self, path, args):
        self.path = path
        self.data = {'expected_upstream_base': PINNED_COMMIT,
                     'configuration': args.configuration, 'target': 'ARM64', 'driver_type': 'WDM',
                     'driver_target_platform': 'Desktop', 'package_version': PACKAGE_VERSION,
                     'kit_version': KIT_VERSION, 'unsigned': True,
                     'validation_policy': args.validation_policy, 'qualified_for_installation': False,
                     'stages': {name: {'status': 'not_run'} for name in (
                         'static', 'source_metadata', 'dependencies', 'msbuild_launch', 'compiler_launch',
                         'compile_link', 'pe', 'source_unchanged', 'staging', 'inf_syntax',
                         'inf_desktop_signability', 'catalog', 'api_universal_diagnostic',
                         'validation_policy', 'offline_package')}}
        for name, reason in (('load', 'Not authorized'), ('capture', 'Build-only scope'),
                             ('production_signing', 'Unsigned offline scope')):
            self.data['stages'][name] = {'status': 'not_run', 'reason': reason}
        self.save()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(self.data, indent=2) + '\n', encoding='utf-8')
        os.replace(temporary, self.path)

    def stage(self, name, action, fatal=True):
        state = self.data['stages'][name]
        state['attempted'] = True
        self.save()
        try:
            result = action(state)
            if isinstance(result, dict):
                state.update(result)
            if state['status'] == 'not_run':
                state['status'] = 'passed'
            self.save()
            require(not fatal or state['status'] == 'passed', name + ' failed; see ' + str(self.path))
            return result
        except Exception as error:
            state.update(getattr(error, 'command_result', {}))
            state.update(status='failed', error=str(error), exception_type=type(error).__name__)
            self.data['error'] = {'stage': name, 'message': str(error), 'exception_type': type(error).__name__}
            self.save()
            raise

    def command(self, name, command, log, env=None, fatal=True, check=None, **metadata):
        def action(state):
            # Record invocation even when process creation itself fails.
            state.update(command=[str(x) for x in command], log=str(log.relative_to(ROOT)), **metadata)
            self.save()
            state.update(run(command, log, env))
            self.save()
            if check and state['exit_code'] == 0:
                check()
            return state.copy()
        return self.stage(name, action, fatal=fatal)


def inspect_images(binary_dir, state):
    images = state.setdefault('images', {})
    for name, subsystem in [('USBPcap.sys', 1), ('USBPcapCMD.exe', 2)]:
        state['current_image'] = name
        info = pe_metadata((binary_dir / name).read_bytes())
        images[name] = info
        require(info['machine'] == '0xaa64', name + ': not native ARM64')
        require(info['subsystem'] == subsystem, name + ': incorrect subsystem')
        require(info['security_size'] == 0, name + ': embedded signature unexpectedly present')
        require(info['clr_size'] == 0 and info['entrypoint_rva'] != 0, name + ': not a native executable')
        require(int(info['dll_characteristics'], 16) & 0x100, name + ': NX compatibility missing')
        require(not any(s['flags'] & 0x20000000 and s['flags'] & 0x80000000 for s in info['sections']),
                name + ': writable executable section')
        if name.endswith('.sys'):
            require(info['section_alignment'] >= 0x1000 and info['section_alignment'] % 0x1000 == 0,
                    name + ': kernel image must use page-aligned sections')
            require(info['imports'] and set(info['imports']) <=
                    {'ntoskrnl.exe', 'hal.dll', 'usbd.sys', 'wmilib.sys', 'wdmsec.sys'},
                    'Unexpected kernel import modules: ' + repr(info['imports']))
    state.pop('current_image', None)


def prepare_stage(binary_dir, stage):
    # Fresh, local staging only. No installed USBPcap files are read or overwritten.
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    for name in ('USBPcap.sys', 'USBPcapCMD.exe', 'USBPcap.pdb', 'USBPcapCMD.pdb'):
        require((binary_dir / name).is_file(), 'Missing rebuilt artifact: ' + name)
        shutil.copy2(binary_dir / name, stage / name)
    shutil.copyfile(ROOT / 'USBPcapDriver/USBPcap.arm64.inx', stage / 'USBPcap.inf')
    shutil.copyfile(ROOT / 'nsis/gpl-2.0.txt', stage / 'GPL-2.0.txt')
    shutil.copyfile(ROOT / 'nsis/bsd-2clause.txt', stage / 'BSD-2-Clause.txt')
    (stage / 'getopt-NOTICE.txt').write_text(
        (ROOT / 'USBPcapCMD/getopt.c').read_text().split('#define _CRT_SECURE_NO_WARNINGS', 1)[0],
        encoding='utf-8')


def package_report(report, stage, archive, warning, state):
    """Verify a candidate, embed that precise outcome, then verify/publish final ZIP.

    The bundle records candidate verification, NOT self-referential final ZIP
    verification/hash. Those are added to the external report only after success.
    """
    state.update(path=str(archive.relative_to(ROOT)), phase='staging', published=False)
    (stage / 'OFFLINE-ONLY.txt').write_text(warning, encoding='utf-8')

    def write_manifest():
        (stage / 'validation.json').write_text(json.dumps(report.data, indent=2) + '\n', encoding='utf-8')
        sums = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                       for p in sorted(stage.iterdir()) if p.name != 'SHA256SUMS')
        (stage / 'SHA256SUMS').write_text(sums, encoding='ascii')

    temporary = archive.with_suffix('.zip.tmp')
    try:
        write_manifest()
        state['phase'] = 'candidate_archive'
        archive_package(stage, temporary)
        state.update(status='passed', phase='payload_and_candidate_verified',
                     status_scope='Payload staging and candidate ZIP verification; final completion recorded externally',
                     candidate_archive_verification={'status': 'passed',
                         'scope': 'Candidate ZIP integrity, members and staged contents before final manifest embedding'},
                     completion_record='Final ZIP verification, publication and SHA-256 are recorded externally after embedding this report')
        report.save()
        write_manifest()
        state.update(status='not_run', phase='final_archive', status_scope='Final ZIP verification and publication')
        report.save()
        # Rebuild with the verified-candidate result and updated SHA256SUMS.
        archive_package(stage, temporary)
        state['final_archive_verification'] = {
            'status': 'passed', 'scope': 'Final ZIP integrity, members and exact staged contents including manifest'}
        state['phase'] = 'publication'
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        os.replace(temporary, archive)
        state.update(status='passed', phase='completed', published=True, sha256=digest)
    except Exception as error:
        if state['phase'] in ('candidate_archive', 'final_archive'):
            key = 'candidate_archive_verification' if state['phase'] == 'candidate_archive' else 'final_archive_verification'
            state[key] = {'status': 'failed', 'error': str(error)}
        raise
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Release')
    parser.add_argument('--vs-root', type=Path, default=DEFAULT_VS)
    parser.add_argument('--msbuild', type=Path)
    parser.add_argument('--vc-tools-version', help='Pin installed MSVC version; otherwise VS default version is recorded')
    parser.add_argument('--host', choices=('auto', 'ARM64', 'x64'), default='auto')
    parser.add_argument('--packages', type=Path, default=ROOT / 'packages')
    parser.add_argument('--static-only', action='store_true')
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--validation-policy', choices=('strict', 'record'), default='strict',
                        help='strict refuses packaging after INF/catalog failure; record makes an explicitly unqualified offline bundle')
    args = parser.parse_args()
    logs = ROOT / 'artifacts/logs/ARM64' / args.configuration
    report = ValidationReport(logs / 'validation.json', args)
    try:
        report.command('static', [sys.executable, ROOT / 'build/arm64/test_build.py'], logs / 'static.log')
        if args.static_only:
            print('Static contract checks passed. Compilation/INF/API/catalog validation NOT RUN.')
            return 0

        def source_metadata(state):
            report.data.update(source_commit=subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), source_sha256=source_snapshot())
            changed = subprocess.check_output(
                ['git', 'diff', '--name-only', 'HEAD', '--', 'USBPcapDriver', 'USBPcapCMD'],
                cwd=ROOT, text=True).splitlines()
            changed += subprocess.check_output(
                ['git', 'ls-files', '--others', '--exclude-standard', '--', 'USBPcapDriver', 'USBPcapCMD'],
                cwd=ROOT, text=True).splitlines()
            capture_changes = sorted({p for p in changed if p.lower().endswith(('.c', '.h'))})
            report.data.update(
                source_variant='locally-modified-capture-source' if capture_changes else 'upstream-capture-source',
                capture_source_changes=capture_changes,
                source_review_complete=False)
        report.stage('source_metadata', source_metadata)

        dep = {}
        def discover(state):
            # Paths stay local; only serializable toolchain selections enter the report.
            dep.update(dependencies(args))
            report.data.update(msvc_version=dep['vc_version'], compiler_host=dep['host'])
        report.stage('dependencies', discover)
        env = os.environ.copy()
        env['PATH'] = str(dep['compiler_dir']) + os.pathsep + str(dep['rc_dir']) + os.pathsep + env.get('PATH', '')
        report.command('msbuild_launch', [dep['msbuild'], '-version', '-nologo'], logs / 'msbuild-launch.log', env)
        report.command('compiler_launch', [dep['compiler_dir'] / 'cl.exe', '/?'], logs / 'compiler-launch.log', env)
        if args.check_only:
            print('Static tests and dependency/launch checks passed; no compilation performed.')
            return 0
        command = [dep['msbuild'], ROOT / 'USBPcap.ARM64.sln', '/t:Rebuild', '/m', '/nologo',
                   '/p:Configuration=' + args.configuration, '/p:Platform=ARM64', '/p:SignMode=Off',
                   '/p:PreferredToolArchitecture=' + dep['host'], '/p:VCToolsVersion=' + dep['vc_version'],
                   '/p:USBPcapPackagesDir=' + str(args.packages.resolve()) + '\\',
                   '/p:RCToolPath=' + str(dep['rc_dir']) + '\\',
                   '/p:MtToolPath=' + str(dep['rc_dir']) + '\\', '/bl:' + str(logs / 'build.binlog')]
        report.command('compile_link', command, logs / 'build.log', env)
        binary_dir = ROOT / 'artifacts/bin/ARM64' / args.configuration
        report.stage('pe', lambda state: inspect_images(binary_dir, state))
        report.stage('source_unchanged', lambda state: require(
            source_snapshot() == report.data['source_sha256'],
            'Source/build inputs changed during compilation; refuse packaging'))
        stage = ROOT / 'artifacts/package/ARM64' / args.configuration
        report.stage('staging', lambda state: prepare_stage(binary_dir, stage))
        # Legacy class-filter INX is not silently upgraded to a primitive/DCH INF.
        report.command('inf_syntax', [dep['infverif'], '/v', stage / 'USBPcap.inf'],
                       logs / 'inf-syntax.log', env, fatal=False)
        report.command('inf_desktop_signability', [dep['infverif'], '/v', '/h', stage / 'USBPcap.inf'],
                       logs / 'inf-desktop.log', env, fatal=False)
        report.command('catalog', [dep['inf2cat'], '/driver:' + str(stage), '/os:10_GE_ARM64', '/verbose'],
                       logs / 'inf2cat.log', env, fatal=False,
                       check=lambda: require((stage / 'USBPcaparm64.cat').is_file(),
                                             'Inf2Cat returned success without expected ARM64 catalog'))
        report.command('api_universal_diagnostic', [
            dep['apivalidator'], '-DriverPackagePath:' + str(stage / 'USBPcap.sys'),
            '-SupportedApiXmlFiles:' + str(dep['api_xml']), '-ModuleWhiteListXmlFiles:' + str(dep['whitelist']),
            # Pinned WDK ApiValidator.xml calls this ApiExtractorExeFolderPath.
            '-ApiExtractorExePath:' + str(dep['aitstatic'].parent)], logs / 'api-universal.log', env, fatal=False,
            qualification='Informational: Desktop WDM target, not a Universal driver claim')
        failures = [key for key in ('inf_syntax', 'inf_desktop_signability', 'catalog')
                    if report.data['stages'][key]['status'] != 'passed']
        report.data['validation_failures'] = failures
        report.stage('validation_policy', lambda state: require(
            not failures or args.validation_policy == 'record',
            'Offline validation failed: ' + ', '.join(failures) + '. No new ZIP produced. See ' + str(report.path)))
        warning = ('UNSIGNED OFFLINE RESEARCH BUNDLE ONLY. DO NOT INSTALL OR LOAD.\n'
                   'No Microsoft production signing, trust-chain validation, driver loading, or hardware capture qualification.\n'
                   'The legacy class-filter INF changes USB class UpperFilters if installed.\n'
                   'Validation policy: ' + args.validation_policy + '\nINF/catalog failures: ' + repr(failures) + '\n'
                   'Universal API diagnostic: ' + report.data['stages']['api_universal_diagnostic']['status'] + '\n'
                   'Source variant: ' + report.data['source_variant'] + '\n'
                   'Capture source changes: ' + repr(report.data['capture_source_changes']) + '\n'
                   'Read validation.json and artifacts/logs before drawing any build/validation conclusions.\n')
        variant_suffix = '-MODIFIED-SOURCE' if report.data['capture_source_changes'] else ''
        archive = stage.parent / ('USBPcap-ARM64-' + args.configuration + variant_suffix + '-UNSIGNED-OFFLINE.zip')
        report.stage('offline_package', lambda state: package_report(report, stage, archive, warning, state))
        print(warning + '\nOffline bundle: ' + str(archive))
        return 0
    except Exception as error:
        report.data.setdefault('error', {'message': str(error), 'exception_type': type(error).__name__})
        try:
            report.save()
        except OSError as save_error:
            print('ERROR: Cannot persist validation report: ' + str(save_error), file=sys.stderr)
        raise


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
