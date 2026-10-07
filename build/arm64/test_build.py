"""Static build-contract tests: no compiler, hardware, or third-party Python modules."""
import importlib.util
import contextlib
import io
import json
import sys
from types import SimpleNamespace
from unittest import mock
import zipfile
from pathlib import Path
import re
import hashlib
import os
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
NS = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
VERSION = '10.0.26100.3323'
SCRATCH = os.environ.get('TMPDIR')  # Callers may select a scratch root; otherwise tempfile uses the OS default.


def manifest_sources(folder):
    text = (ROOT / folder / 'SOURCES').read_text()
    match = re.search(r'^SOURCES\s*=\s*(.*)', text, re.M | re.S)
    return re.findall(r'[\w.]+\.(?:c|rc)\b', match.group(1))


def project(folder):
    name = 'USBPcap.ARM64.vcxproj' if folder == 'USBPcapDriver' else 'USBPcapCMD.ARM64.vcxproj'
    return ET.parse(ROOT / folder / name)


# Constructed PE32+ bytes, never executable/compiler evidence. Offsets are fixed
# so regression mutations exercise the real parser, not mocked metadata.
PE_OFFSET = 0x80
PE_OPT = PE_OFFSET + 24
PE_SECTIONS = PE_OPT + 240


def pe_fixture(subsystem=1, imports=('ntoskrnl.exe',), bss=False):
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, PE_OFFSET)
    data[PE_OFFSET:PE_OFFSET + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, PE_OFFSET + 4, 0xAA64, 3 if bss else 2,
                     0, 0, 0, 240, 0x22)
    struct.pack_into('<H', data, PE_OPT, 0x20B)
    struct.pack_into('<I', data, PE_OPT + 16, 0x1000)
    struct.pack_into('<Q', data, PE_OPT + 24, 0x140000000)
    struct.pack_into('<II', data, PE_OPT + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, PE_OPT + 56, 0x4000 if bss else 0x3000, 0x200)
    struct.pack_into('<HH', data, PE_OPT + 68, subsystem, 0x100)
    struct.pack_into('<I', data, PE_OPT + 108, 16)
    for idx, (name, virtual_size, rva, raw_size, raw, flags) in enumerate([
            (b'.text', 0x100, 0x1000, 0x200, 0x200, 0x60000020),
            (b'.rdata', 0x200, 0x2000, 0x200, 0x400, 0x40000040)] +
            ([(b'.bss', 0x800, 0x3000, 0, 0, 0xC0000080)] if bss else [])):
        pos = PE_SECTIONS + idx * 40
        data[pos:pos + 8] = name.ljust(8, b'\0')
        struct.pack_into('<IIII', data, pos + 8, virtual_size, rva, raw_size, raw)
        struct.pack_into('<I', data, pos + 36, flags)
    data[0x200:0x204] = b'\xc0\x03\x5f\xd6'  # ARM64 RET encoding, not a runnable program.
    if imports:
        struct.pack_into('<II', data, PE_OPT + 120, 0x2000, 20 * (len(imports) + 1))
        name_offset = 0x480
        for idx, name in enumerate(imports):
            struct.pack_into('<IIIII', data, 0x400 + 20 * idx, 0x2100, 0, 0,
                             0x2000 + name_offset - 0x400, 0x2110)
            encoded = name.encode('ascii') + b'\0'
            data[name_offset:name_offset + len(encoded)] = encoded
            name_offset += len(encoded)
    return data


def low_alignment_pe_fixture(subsystem=1, imports=('ntoskrnl.exe',)):
    data = pe_fixture(subsystem, imports)
    struct.pack_into('<II', data, PE_OPT + 32, 0x200, 0x200)
    struct.pack_into('<I', data, PE_OPT + 16, 0x200)
    struct.pack_into('<I', data, PE_OPT + 56, 0x600)
    struct.pack_into('<I', data, PE_SECTIONS + 12, 0x200)
    struct.pack_into('<I', data, PE_SECTIONS + 40 + 12, 0x400)
    if imports:
        struct.pack_into('<I', data, PE_OPT + 120, 0x400)
        for idx in range(len(imports)):
            pos = 0x400 + idx * 20
            desc = struct.unpack_from('<IIIII', data, pos)
            struct.pack_into('<IIIII', data, pos, desc[0] - 0x1C00, 0, 0,
                             desc[3] - 0x1C00, desc[4] - 0x1C00)
    return data


def malformed_pe_fixtures():
    """Each mutation isolates a structural gate using otherwise valid bytes."""
    variants = {}
    def mutated(name, offset, value):
        data = pe_fixture()
        struct.pack_into('<I', data, offset, value)
        variants[name] = data
    mutated('raw_pointer_outside_file', PE_SECTIONS + 20, 0x800)
    mutated('raw_range_past_file', PE_SECTIONS + 16, 0x600)
    mutated('raw_pointer_unaligned', PE_SECTIONS + 20, 0x201)
    mutated('raw_size_unaligned', PE_SECTIONS + 16, 0x201)
    mutated('raw_overlaps_headers', PE_SECTIONS + 20, 0)
    mutated('raw_sections_overlap', PE_SECTIONS + 40 + 20, 0x200)
    mutated('virtual_sections_overlap', PE_SECTIONS + 40 + 12, 0x1000)
    mutated('virtual_rva_unaligned', PE_SECTIONS + 12, 0x1001)
    mutated('virtual_range_outside_image', PE_SECTIONS + 8, 0x3000)
    mutated('section_alignment_one', PE_OPT + 32, 1)
    mutated('section_alignment_not_power_two', PE_OPT + 32, 0x1800)
    mutated('file_alignment_not_power_two', PE_OPT + 36, 0x300)
    mutated('headers_too_short', PE_OPT + 60, 0x100)
    mutated('headers_past_file', PE_OPT + 60, 0x800)
    mutated('image_size_unaligned', PE_OPT + 56, 0x3001)
    mutated('image_size_too_small', PE_OPT + 56, 0x2000)
    mutated('entrypoint_unmapped', PE_OPT + 16, 0xFFFFFFFF)
    mutated('entrypoint_zero', PE_OPT + 16, 0)
    mutated('entrypoint_instruction_unaligned', PE_OPT + 16, 0x1001)
    mutated('entrypoint_non_executable', PE_OPT + 16, 0x2000)
    mutated('entrypoint_in_raw_padding', PE_OPT + 16, 0x1100)
    data = pe_fixture()
    struct.pack_into('<I', data, PE_SECTIONS + 8, 0x400)
    struct.pack_into('<I', data, PE_OPT + 16, 0x1200)
    variants['entrypoint_in_zero_fill'] = data
    mutated('directory_count_exceeds_header', PE_OPT + 108, 17)
    mutated('clr_rva_without_size', PE_OPT + 112 + 14 * 8, 0x2080)
    mutated('certificate_offset_without_size', PE_OPT + 112 + 4 * 8, 0x600)
    mutated('import_rva_without_size', PE_OPT + 124, 0)
    mutated('import_size_without_rva', PE_OPT + 120, 0)
    mutated('import_directory_crosses_section', PE_OPT + 124, 0x201)
    mutated('import_name_unmapped', 0x400 + 12, 0xFFFFFFFF)
    data = pe_fixture()
    struct.pack_into('<I', data, 0x400 + 12, 0x21FC)
    data[0x5FC:0x600] = b'name'
    data.extend(b'\0')  # Overlay terminator is NOT part of the mapped section.
    variants['import_name_terminator_outside_section'] = data
    data = pe_fixture()
    struct.pack_into('<I', data, PE_SECTIONS + 40 + 8, 0x100)
    struct.pack_into('<I', data, 0x400 + 12, 0x20FC)
    data[0x4FC:0x501] = b'name\0'
    variants['import_name_terminator_in_raw_padding'] = data
    data = pe_fixture(imports=('ntoskrnl.exe', 'kernel32.dll'))
    struct.pack_into('<I', data, PE_OPT + 124, 20)
    variants['hidden_kernel32_short_directory'] = data
    data = pe_fixture(imports=('ntoskrnl.exe', 'kernel32.dll'))
    struct.pack_into('<I', data, PE_OPT + 124, 40)
    variants['import_directory_missing_terminator'] = data
    return variants


class PEParserRegression(unittest.TestCase):
    def setUp(self):
        self.module = BuildContract().load_build_module()

    def test_valid_native_and_gui_images(self):
        for subsystem, names in ((1, ('NTOSKRNL.EXE', 'hal.dll', 'usbd.sys')),
                                 (2, ('kernel32.dll', 'user32.dll'))):
            with self.subTest(subsystem=subsystem):
                info = self.module.pe_metadata(pe_fixture(subsystem, names))
                self.assertEqual(info['machine'], '0xaa64')
                self.assertEqual(info['subsystem'], subsystem)
                self.assertEqual(info['imports'], [name.lower() for name in names])
                self.assertEqual(info['entrypoint_rva'], 0x1000)

    def test_valid_zero_fill_and_overlay_are_supported(self):
        data = pe_fixture(bss=True)
        data.extend(b'legitimate nonmapped overlay')
        self.assertEqual(len(self.module.pe_metadata(data)['sections']), 3)

    def test_imports_may_be_absent_in_general_parser(self):
        self.assertEqual(self.module.pe_metadata(pe_fixture(2, imports=()))['imports'], [])

    def test_malformed_structural_fixtures_are_rejected(self):
        for name, data in malformed_pe_fixtures().items():
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                self.module.pe_metadata(data)

    def test_real_inspection_allows_valid_driver_and_gui_pair(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)
            (path / 'USBPcap.sys').write_bytes(pe_fixture(bss=True))
            (path / 'USBPcapCMD.exe').write_bytes(pe_fixture(2, ('kernel32.dll',)))
            state = {}
            self.module.inspect_images(path, state)
            self.assertCountEqual(state['images'], ['USBPcap.sys', 'USBPcapCMD.exe'])
            self.assertNotIn('current_image', state)

    def test_complete_forbidden_import_is_not_hidden(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)
            (path / 'USBPcap.sys').write_bytes(pe_fixture(imports=('ntoskrnl.exe', 'kernel32.dll')))
            with self.assertRaisesRegex(RuntimeError, 'Unexpected kernel import'):
                self.module.inspect_images(path, {})

    def test_kernel_requires_page_alignment_not_gui_characteristics(self):
        # A valid low-alignment general PE is not a page-aligned kernel target.
        data = low_alignment_pe_fixture()
        self.assertEqual(self.module.pe_metadata(data)['section_alignment'], 0x200)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)
            (path / 'USBPcap.sys').write_bytes(data)
            with self.assertRaisesRegex(RuntimeError, 'page-aligned'):
                self.module.inspect_images(path, {})

    def test_page_alignment_gate_does_not_apply_to_gui_image(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)
            (path / 'USBPcap.sys').write_bytes(pe_fixture())
            (path / 'USBPcapCMD.exe').write_bytes(low_alignment_pe_fixture(2, ('kernel32.dll',)))
            self.module.inspect_images(path, {})


class BuildContract(unittest.TestCase):
    def load_build_module(self):
        spec = importlib.util.spec_from_file_location('arm64_build', ROOT / 'build/arm64/build.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_source_manifests_exact(self):
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            with self.subTest(folder=folder):
                tree = project(folder)
                items = tree.findall('.//m:ClCompile[@Include]', NS) + tree.findall('.//m:ResourceCompile[@Include]', NS)
                actual = [x.attrib['Include'] for x in items]
                self.assertCountEqual(actual, manifest_sources(folder))
                self.assertEqual(len(actual), len(set(actual)))
                for name in actual:
                    self.assertTrue((ROOT / folder / name).is_file(), name)

    def test_only_arm64_configurations(self):
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            configs = project(folder).findall('.//m:ProjectConfiguration', NS)
            self.assertCountEqual([x.attrib['Include'] for x in configs], ['Debug|ARM64', 'Release|ARM64'])

    def test_wdm_not_kmdf(self):
        tree = project('USBPcapDriver')
        for tag, value in [('DriverType', 'WDM'), ('DriverTargetPlatform', 'Desktop'),
                           ('SubSystem', 'Native'), ('EntryPointSymbol', 'GsDriverEntry'),
                           ('IgnoreAllDefaultLibraries', 'true'), ('BufferSecurityCheck', 'true')]:
            self.assertIn(value, [e.text for e in tree.findall('.//m:' + tag, NS)])
        text = (ROOT / 'USBPcapDriver/USBPcap.ARM64.vcxproj').read_text()
        self.assertNotIn('FxDriverEntry', text)
        self.assertNotIn('KMDF', text)
        self.assertIn('POOL_NX_OPTIN=1', text)
        self.assertIn('/kernel', text)
        self.assertIn('/DRIVER', text)

    def test_libraries_preserved(self):
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            required = set(x.lower() for x in re.findall(r'\\([\w]+\.lib)', (ROOT / folder / 'SOURCES').read_text()))
            actual = set(x.lower() for x in re.findall(r'\b([\w]+\.lib)', ET.tostring(project(folder).getroot(), encoding='unicode')))
            self.assertLessEqual(required, actual)
        self.assertIn('bufferoverflowfastfailk.lib', actual_driver_libraries())
        self.assertIn('arm64rt.lib', actual_driver_libraries())

    def test_packages_pinned(self):
        items = ET.parse(ROOT / 'build/arm64/packages.config').getroot().findall('package')
        self.assertEqual({x.attrib['id']: x.attrib['version'] for x in items}, {
            'Microsoft.Windows.WDK.ARM64': VERSION,
            'Microsoft.Windows.SDK.CPP': VERSION,
            'Microsoft.Windows.SDK.CPP.arm64': VERSION})
        common = (ROOT / 'build/arm64/Common.props').read_text()
        self.assertIn(VERSION, common)
        self.assertNotIn('PROCESSOR_ARCHITECTURE', common)
        for pkg in ('Microsoft.Windows.WDK.ARM64', 'Microsoft.Windows.SDK.CPP', 'Microsoft.Windows.SDK.CPP.arm64'):
            self.assertIn(pkg, common)

    def test_cli_matches_real_entry(self):
        tree = project('USBPcapCMD')
        self.assertIn('Windows', [e.text for e in tree.findall('.//m:SubSystem', NS)])
        self.assertIn('cmd.c', manifest_sources('USBPcapCMD'))
        self.assertIn('int CALLBACK WinMain(', (ROOT / 'USBPcapCMD/cmd.c').read_text())
        self.assertNotIn('wWinMain', ET.tostring(tree.getroot(), encoding='unicode'))

    def test_manifest_real_xml(self):
        tree = ET.parse(ROOT / 'build/arm64/USBPcapCMD.manifest')
        identity = tree.find('{urn:schemas-microsoft-com:asm.v1}assemblyIdentity')
        self.assertEqual(identity.attrib['processorArchitecture'], 'arm64')
        self.assertEqual(identity.attrib['version'], '1.5.4.0')
        requested = tree.find('.//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')
        self.assertEqual(requested.attrib, {'level': 'asInvoker', 'uiAccess': 'false'})

    def test_inf_architecture_and_legacy_scope_explicit(self):
        text = (ROOT / 'USBPcapDriver/USBPcap.arm64.inx').read_text()
        self.assertIn('[DefaultInstall.NTarm64]', text)
        self.assertIn('[DefaultInstall.NTarm64.Services]', text)
        self.assertIn('CatalogFile.NTarm64 = USBPcaparm64.cat', text)
        self.assertIn('DriverVer = 02/09/2025,1.5.4.0', text)
        self.assertNotIn('NTamd64', text)
        self.assertNotIn('NTx86', text)
        self.assertIn('UpperFilters, 0x00010008, USBPcap', text)

    def test_abi_assertions_in_both_projects(self):
        header = (ROOT / 'build/arm64/abi-checks.h').read_text()
        for name in ('USBPCAP_ADDRESS_FILTER', 'USBPCAP_BUFFER_PACKET_HEADER', 'pcap_hdr_t', 'pcaprec_hdr_t'):
            self.assertIn('sizeof(' + name + ')', header)
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            self.assertIn('abi-checks.h', ET.tostring(project(folder).getroot(), encoding='unicode'))

    def test_forced_abi_header_preserves_single_guid_definition_unit(self):
        tree = project('USBPcapDriver')
        marked = [item for item in tree.findall('.//m:ClCompile[@Include]', NS)
                  if 'USBPCAP_DEFINE_GUIDS' in (item.findtext('m:PreprocessorDefinitions', default='', namespaces=NS))]
        self.assertEqual([item.attrib['Include'] for item in marked], ['USBPcapHelperFunctions.c'])
        header = (ROOT / 'build/arm64/abi-checks.h').read_text()
        self.assertLess(header.index('#include <initguid.h>'), header.index('#include <ntddk.h>'))
        self.assertIn('#ifdef USBPCAP_DEFINE_GUIDS', header)

    def test_cli_static_runtime_library_path_is_explicit(self):
        path = project('USBPcapCMD').find('.//m:LibraryPath', NS).text
        self.assertIn('$(VCToolsInstallDir)lib\\arm64', path)
        link = project('USBPcapCMD').find('.//m:Link/m:AdditionalLibraryDirectories', NS).text
        self.assertIn('$(VCToolsInstallDir)lib\\arm64', link)
        self.assertIn('$(USBPcapSdkArm64)c\\ucrt\\arm64', link)

    def test_solution_agreement(self):
        text = (ROOT / 'USBPcap.ARM64.sln').read_text()
        for folder, name in [('USBPcapDriver', 'USBPcap.ARM64.vcxproj'), ('USBPcapCMD', 'USBPcapCMD.ARM64.vcxproj')]:
            self.assertIn(folder + '\\' + name, text)
            guid = project(folder).find('.//m:ProjectGuid', NS).text
            for config in ('Debug', 'Release'):
                self.assertIn(guid + '.' + config + '|ARM64.Build.0 = ' + config + '|ARM64', text)
        self.assertNotIn('Deploy.0', text)

    def test_safety_guards(self):
        text = (ROOT / 'build/arm64/Checks.targets').read_text()
        self.assertIn("'$(SignMode)' != 'Off'", text)
        self.assertIn("'$(Platform)' != 'ARM64'", text)
        self.assertIn('USBPcapBuildOnlyGuard', text)
        common = (ROOT / 'build/arm64/Common.props').read_text()
        self.assertIn('<SignMode>Off</SignMode>', common)
        self.assertIn('<EnableInf2cat>false</EnableInf2cat>', common)
        self.assertIn('<DriverDeploy>false</DriverDeploy>', common)

    def test_pe_parser_rejects_non_pe(self):
        module = self.load_build_module()
        with self.assertRaises(ValueError):
            module.pe_metadata(b'not a PE')

    def test_pe_parser_rejects_truncation(self):
        module = self.load_build_module()
        data = bytearray(64)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3C, 1024)
        with self.assertRaises(ValueError):
            module.pe_metadata(data)

    def test_offline_archive_determinism_and_allowlist(self):
        module = self.load_build_module()
        # Plain-text fixture only; this is NOT a driver or build-artifact fixture.
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            root = Path(temp)
            stage = root / 'stage'
            stage.mkdir()
            (stage / 'OFFLINE-ONLY.txt').write_text('UNIT TEST FIXTURE: NO BINARY\n')
            a, b = root / 'a.zip', root / 'b.zip'
            module.archive_package(stage, a)
            module.archive_package(stage, b)
            self.assertEqual(hashlib.sha256(a.read_bytes()).digest(), hashlib.sha256(b.read_bytes()).digest())
            (stage / 'private.pfx').write_bytes(b'not a certificate: negative test fixture')
            with self.assertRaisesRegex(RuntimeError, 'Unexpected offline bundle member'):
                module.archive_package(stage, root / 'rejected.zip')

    def test_offline_archive_accepts_actual_inf2cat_lowercase_name(self):
        module = self.load_build_module()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            root = Path(temp)
            stage = root / 'stage'
            stage.mkdir()
            (stage / 'usbpcaparm64.cat').write_text('SYNTHETIC CATALOG NAME FIXTURE ONLY')
            archive = root / 'name-test.zip'
            module.archive_package(stage, archive)
            with zipfile.ZipFile(archive) as z:
                self.assertEqual(z.namelist(), ['usbpcaparm64.cat'])

    def test_kernel_manifest_disabled_and_local_headers(self):
        tree = project('USBPcapDriver')
        self.assertEqual(tree.find('.//m:GenerateManifest', NS).text, 'false')
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            directories = project(folder).find('.//m:AdditionalIncludeDirectories', NS).text
            self.assertIn('$(ProjectDir)', directories)

    def test_upstream_version_and_nx_initialization(self):
        driver_manifest = (ROOT / 'USBPcapDriver/SOURCES').read_text()
        self.assertIn('USBPCAP_VERSION=1.5.4.0', driver_manifest)
        source = (ROOT / 'USBPcapDriver/USBPcapMain.c').read_text()
        self.assertIn('ExInitializeDriverRuntime(DrvRtPoolNxOptIn)', source)

    def test_source_snapshot_contains_both_manifests(self):
        snapshot = self.load_build_module().source_snapshot()
        for name in ('USBPcapDriver/SOURCES', 'USBPcapCMD/SOURCES', 'USBPcap.ARM64.sln'):
            self.assertIn(name, snapshot)
            self.assertRegex(snapshot[name], r'^[0-9a-f]{64}$')


class WrapperRegression(unittest.TestCase):
    """Synthetic files and mocked tools only: these tests never compile/load a driver."""

    def setUp(self):
        self.module = BuildContract().load_build_module()
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def dependency_fixture(self, configuration, host='ARM64'):
        m = self.module
        vs, packages = self.root / 'vs', self.root / 'packages'
        vc = vs / 'VC/Tools/MSVC/test-version'
        wdk, sdk, libs = [packages / (p + '.' + m.PACKAGE_VERSION) / 'c' for p in m.PACKAGES]
        paths = [vs / 'MSBuild/Current/Bin/arm64/MSBuild.exe',
                 vc / ('bin/Host' + host + '/arm64/cl.exe'),
                 vc / ('bin/Host' + host + '/arm64/link.exe'), vc / 'include/vcruntime.h',
                 vs / 'MSBuild/Microsoft/VC/v170/Platforms/ARM64/PlatformToolsets/v143/Toolset.props',
                 wdk / ('Include/' + m.KIT_VERSION + '/km/ntddk.h')]
        paths += [sdk / ('Include/' + m.KIT_VERSION + '/' + name) for name in
                  ('shared/usb.h', 'um/Windows.h', 'ucrt/stdio.h')]
        paths += [wdk / ('Lib/' + m.KIT_VERSION + '/km/ARM64/' + name) for name in
                  ('wdm.lib', 'wdmsec.lib', 'ntstrsafe.lib', 'ntoskrnl.lib', 'usbd.lib',
                   'hal.lib', 'wmilib.lib', 'bufferoverflowfastfailk.lib')]
        paths += [libs / ('um/arm64/' + name) for name in
                  ('arm64rt.lib', 'hid.lib', 'setupapi.lib', 'comdlg32.lib', 'advapi32.lib',
                   'cfgmgr32.lib', 'shell32.lib', 'shlwapi.lib', 'kernel32.lib', 'user32.lib',
                   'gdi32.lib', 'ole32.lib', 'oleaut32.lib', 'uuid.lib', 'winspool.lib',
                   'odbc32.lib', 'odbccp32.lib')]
        suffix = 'd' if configuration == 'Debug' else ''
        paths += [vc / ('lib/arm64/' + name) for name in
                  ('libcmt' + suffix + '.lib', 'libvcruntime' + suffix + '.lib', 'oldnames.lib')]
        paths += [libs / ('ucrt/arm64/libucrt' + suffix + '.lib')]
        for package, name in zip(m.PACKAGES, ('Microsoft.Windows.WDK.arm64.props',
                                            'Microsoft.Windows.SDK.cpp.props',
                                            'Microsoft.Windows.SDK.cpp.arm64.props')):
            paths.append(packages / (package + '.' + m.PACKAGE_VERSION) / 'build/native' / name)
        sdk_host = 'arm64' if host == 'ARM64' else 'x64'
        paths += [sdk / ('bin/' + m.KIT_VERSION + '/' + sdk_host + '/' + name) for name in ('rc.exe', 'mt.exe')]
        paths += [wdk / ('tools/' + m.KIT_VERSION + '/ARM64/infverif.exe'),
                  wdk / ('bin/' + m.KIT_VERSION + '/x86/Inf2Cat.exe')]
        paths += [wdk / ('bin/' + m.KIT_VERSION + '/' + sdk_host + '/' + name)
                  for name in ('apivalidator.exe', 'AitStatic.exe')]
        paths += [wdk / ('build/' + m.KIT_VERSION + '/universalDDIs/arm64/' + name)
                  for name in ('UniversalDDIs.xml', 'ModuleWhitelist.xml')]
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('PREREQUISITE EXISTENCE FIXTURE ONLY')
        args = SimpleNamespace(vs_root=vs, packages=packages, vc_tools_version='test-version',
                               msbuild=None, host=host, configuration=configuration)
        return args, paths

    def test_dependency_checks_cover_explicit_and_inherited_project_libraries(self):
        args, paths = self.dependency_fixture('Release')
        # The projects preserve %(AdditionalDependencies) from the v143 desktop defaults.
        libraries = {'winspool.lib', 'odbc32.lib', 'odbccp32.lib'}
        for folder in ('USBPcapDriver', 'USBPcapCMD'):
            libraries.update(re.findall(r'\b([\w]+\.lib)', ET.tostring(project(folder).getroot(), encoding='unicode').lower()))
        for name in sorted(libraries):
            path = next(p for p in paths if p.name == name)
            with self.subTest(library=name):
                path.unlink()
                try:
                    with self.assertRaisesRegex(RuntimeError, re.escape(str(path))):
                        self.module.dependencies(args)
                finally:
                    path.write_text('PREREQUISITE EXISTENCE FIXTURE ONLY')

    def test_dependency_checks_selected_static_crt_and_vc_libraries(self):
        for configuration in ('Release', 'Debug'):
            args, paths = self.dependency_fixture(configuration)
            suffix = 'd' if configuration == 'Debug' else ''
            self.module.dependencies(args)
            for name in ('libcmt' + suffix + '.lib', 'libvcruntime' + suffix + '.lib',
                         'libucrt' + suffix + '.lib', 'oldnames.lib'):
                path = next(p for p in paths if p.name == name)
                with self.subTest(configuration=configuration, library=name):
                    path.unlink()
                    try:
                        with self.assertRaisesRegex(RuntimeError, re.escape(str(path))):
                            self.module.dependencies(args)
                    finally:
                        path.write_text('PREREQUISITE EXISTENCE FIXTURE ONLY')

    def test_debug_requires_debug_crt_not_release_crt(self):
        args, paths = self.dependency_fixture('Release', 'x64')
        args.configuration = 'Debug'
        with self.assertRaisesRegex(RuntimeError, 'libcmtd.lib'):
            self.module.dependencies(args)
        for path in [p for p in paths if p.name in ('libcmt.lib', 'libvcruntime.lib', 'libucrt.lib')]:
            path.with_name(path.stem + 'd.lib').write_text('DEBUG PREREQUISITE FIXTURE ONLY')
            path.unlink()
        self.assertEqual(self.module.dependencies(args)['host'], 'x64')

    def invoke(self, failure=None, policy='strict', flags=(), archive_failure=None, driver_bytes=None,
               source_changes='', untracked_sources=''):
        m, root = self.module, self.root
        binary = root / 'artifacts/bin/ARM64/Release'
        binary.mkdir(parents=True, exist_ok=True)
        for name in ('USBPcap.sys', 'USBPcapCMD.exe', 'USBPcap.pdb', 'USBPcapCMD.pdb'):
            (binary / name).write_text('UNIT TEST TEXT ONLY: NOT A BUILD ARTIFACT')
        (binary / 'USBPcap.sys').write_bytes(pe_fixture() if driver_bytes is None else driver_bytes)
        (binary / 'USBPcapCMD.exe').write_bytes(pe_fixture(2, ('kernel32.dll',)))
        if failure in ('pe', 'pe_second'):
            (binary / ('USBPcap.sys' if failure == 'pe' else 'USBPcapCMD.exe')).write_bytes(b'not a PE')
        if failure == 'pe_machine':
            data = pe_fixture()
            struct.pack_into('<H', data, PE_OFFSET + 4, 0x8664)
            (binary / 'USBPcap.sys').write_bytes(data)
        for name in ('USBPcapDriver/USBPcap.arm64.inx', 'nsis/gpl-2.0.txt', 'nsis/bsd-2clause.txt', 'USBPcapCMD/getopt.c'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('UNIT TEST TEXT FIXTURE ONLY')
        dep = {key: root / key for key in ('msbuild', 'compiler_dir', 'rc_dir', 'infverif',
                                          'inf2cat', 'apivalidator', 'api_xml', 'whitelist', 'aitstatic')}
        dep.update(vc_version='test-version', host='ARM64')
        dep['aitstatic'] = root / 'api-extractor-tools/AitStatic.exe'
        dep['aitstatic'].parent.mkdir(exist_ok=True)
        dep['aitstatic'].write_text('TOOL EXISTENCE FIXTURE ONLY')
        calls = []

        def fake_run(command, log=None, env=None):
            command = [str(x) for x in command]
            calls.append(command)
            if 'test_build.py' in command[-1]:
                key = 'static'
            elif '-version' in command:
                key = 'msbuild_launch'
            elif '/?' in command:
                key = 'compiler_launch'
            elif '/t:Rebuild' in command:
                key = 'compile_link'
            elif command[0] == str(dep['infverif']):
                key = 'inf_desktop_signability' if '/h' in command else 'inf_syntax'
            elif command[0] == str(dep['inf2cat']):
                key = 'catalog'
                if failure != 'missing_catalog':
                    (root / 'artifacts/package/ARM64/Release/USBPcaparm64.cat').write_text('NOT A CATALOG: TEST TEXT')
            else:
                key = 'api_universal_diagnostic'
            if failure == key + '_exception':
                raise OSError('fixture ' + key + ' exception')
            code = 7 if failure == key else 0
            return {'status': 'passed' if code == 0 else 'failed', 'exit_code': code,
                    'command': command, 'log': str(log) if log else None, 'output': 'fixture output ' + key}

        original_archive = m.archive_package
        archive_calls = []

        def fake_archive(stage, path):
            archive_calls.append(path)
            if archive_failure == len(archive_calls):
                raise OSError('fixture archive write/verification failure')
            if archive_failure == 'final_integrity' and len(archive_calls) == 2:
                with mock.patch.object(m.zipfile.ZipFile, 'testzip', return_value='validation.json'):
                    return original_archive(stage, path)
            return original_archive(stage, path)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, 'ROOT', root))
            stack.enter_context(mock.patch.object(m, 'run', side_effect=fake_run))
            stack.enter_context(mock.patch.object(m, 'dependencies', side_effect=RuntimeError('fixture missing prerequisites')
                                                 if failure == 'dependencies' else None, return_value=dep))
            if failure == 'source_unchanged':
                stack.enter_context(mock.patch.object(m, 'source_snapshot', side_effect=[{'fixture': 'sha256'}, {'fixture': 'changed'}]))
            else:
                stack.enter_context(mock.patch.object(m, 'source_snapshot', return_value={'fixture': 'sha256'}))
            def fake_git(command, *args, **kwargs):
                if failure == 'source_metadata':
                    raise OSError('fixture missing git')
                if command[:2] == ['git', 'rev-parse']:
                    return 'fixture-commit\n'
                if command[:2] == ['git', 'diff']:
                    return source_changes
                if command[:2] == ['git', 'ls-files']:
                    return untracked_sources
                raise AssertionError('Unexpected fixture git command: ' + repr(command))
            stack.enter_context(mock.patch.object(m.subprocess, 'check_output', side_effect=fake_git))
            if failure == 'staging':
                (binary / 'USBPcap.pdb').unlink()
            if failure == 'pe_read':
                (binary / 'USBPcapCMD.exe').unlink()
            stack.enter_context(mock.patch.object(m, 'archive_package', side_effect=fake_archive))
            stack.enter_context(mock.patch.object(sys, 'argv', ['build.py', '--validation-policy', policy, *flags]))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            error = None
            try:
                result = m.main()
            except (RuntimeError, ValueError, OSError) as caught:
                result, error = None, caught
        path = root / 'artifacts/logs/ARM64/Release/validation.json'
        self.assertTrue(path.is_file(), 'Report must exist even after prerequisite/stage exceptions')
        return json.loads(path.read_text()), result, error, calls

    def test_modified_capture_source_has_distinct_unsigned_archive_and_remains_unqualified(self):
        report, result, error, _ = self.invoke(source_changes='USBPcapDriver/USBPcapBuffer.c\n')
        self.assertIsNone(error)
        self.assertEqual(result, 0)
        self.assertEqual(report['source_variant'], 'locally-modified-capture-source')
        self.assertEqual(report['capture_source_changes'], ['USBPcapDriver/USBPcapBuffer.c'])
        self.assertIn('-MODIFIED-SOURCE-UNSIGNED-OFFLINE.zip', report['stages']['offline_package']['path'])
        self.assertFalse(report['source_review_complete'])
        self.assertFalse(report['qualified_for_installation'])

    def test_untracked_capture_header_counts_as_modified_source(self):
        report, _, error, _ = self.invoke(untracked_sources='USBPcapDriver/include/new.h\nUSBPcapCMD/tool.vcxproj\n')
        self.assertIsNone(error)
        self.assertEqual(report['capture_source_changes'], ['USBPcapDriver/include/new.h'])
        self.assertEqual(report['source_variant'], 'locally-modified-capture-source')

    def test_modified_source_bundle_preserves_baseline_archive(self):
        original, _, error, _ = self.invoke()
        self.assertIsNone(error)
        baseline = self.root / original['stages']['offline_package']['path']
        before = baseline.read_bytes()
        modified, _, error, _ = self.invoke(source_changes='USBPcapDriver/USBPcapURB.c\n')
        self.assertIsNone(error)
        self.assertNotEqual(original['stages']['offline_package']['path'],
                            modified['stages']['offline_package']['path'])
        self.assertEqual(baseline.read_bytes(), before)

    def test_early_failure_reports_and_remaining_not_run(self):
        for failure in ('static', 'dependencies', 'msbuild_launch', 'compiler_launch', 'compile_link'):
            with self.subTest(stage=failure):
                report, _, error, _ = self.invoke(failure)
                self.assertIsNotNone(error)
                self.assertEqual(report['stages'][failure]['status'], 'failed')
                self.assertEqual(report['stages']['offline_package']['status'], 'not_run')
                self.assertIn('error', report)

    def test_pe_exception_preserves_compile_output_and_failed_stage(self):
        report, _, error, _ = self.invoke('pe', policy='record')
        self.assertIsNotNone(error)
        self.assertEqual(report['stages']['pe']['status'], 'failed')
        self.assertIn('Not a PE image', report['stages']['pe']['error'])
        self.assertEqual(report['stages']['compile_link']['output'], 'fixture output compile_link')
        self.assertEqual(report['stages']['offline_package']['status'], 'not_run')

    def test_validator_exception_preserves_prior_results(self):
        report, _, error, _ = self.invoke('inf_desktop_signability_exception')
        self.assertIsNotNone(error)
        self.assertEqual(report['stages']['inf_syntax']['status'], 'passed')
        self.assertEqual(report['stages']['inf_syntax']['output'], 'fixture output inf_syntax')
        self.assertEqual(report['stages']['inf_desktop_signability']['status'], 'failed')
        self.assertIn('fixture inf_desktop_signability exception', report['stages']['inf_desktop_signability']['error'])

    def test_missing_catalog_is_failed_even_after_zero_exit(self):
        report, _, error, _ = self.invoke('missing_catalog')
        self.assertIsNotNone(error)
        self.assertEqual(report['stages']['catalog']['status'], 'failed')
        self.assertEqual(report['stages']['catalog']['exit_code'], 0)
        self.assertIn('expected ARM64 catalog', report['stages']['catalog']['error'])

    def test_strict_rejects_and_record_preserves_validation_failures(self):
        report, _, error, _ = self.invoke('inf_syntax')
        self.assertIsNotNone(error)
        self.assertEqual(report['stages']['offline_package']['status'], 'not_run')
        report, result, error, _ = self.invoke('inf_syntax', policy='record')
        self.assertIsNone(error)
        self.assertEqual(result, 0)
        self.assertEqual(report['validation_failures'], ['inf_syntax'])
        self.assertFalse(report['qualified_for_installation'])
        self.assertEqual(report['stages']['api_universal_diagnostic']['status'], 'passed')

    def test_successful_bundle_has_precise_packaging_state_and_no_zip_hash(self):
        report, result, error, _ = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(result, 0)
        package = report['stages']['offline_package']
        self.assertEqual(package['status'], 'passed')
        archive = self.root / package['path']
        self.assertEqual(package['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
        with zipfile.ZipFile(archive) as z:
            bundled = json.loads(z.read('validation.json'))
            state = bundled['stages']['offline_package']
            self.assertEqual(state['status'], 'passed')
            self.assertEqual(state['phase'], 'payload_and_candidate_verified')
            self.assertIn('candidate ZIP', state['status_scope'])
            self.assertIn('recorded externally', state['completion_record'])
            self.assertFalse(state['published'])
            self.assertEqual(state['candidate_archive_verification']['status'], 'passed')
            self.assertNotIn('sha256', state)
            self.assertNotIn('final_archive_verification', state)
            for line in z.read('SHA256SUMS').decode().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(digest, hashlib.sha256(z.read(name)).hexdigest())
        self.assertEqual(package['final_archive_verification']['status'], 'passed')
        self.assertEqual(package['phase'], 'completed')
        self.assertTrue(package['published'])
        for key in ('load', 'capture', 'production_signing'):
            self.assertEqual(bundled['stages'][key]['status'], 'not_run')

    def test_archive_write_or_final_verification_failure_persists_failed_stage(self):
        for fail_call in (1, 2):
            with self.subTest(archive_call=fail_call):
                report, _, error, _ = self.invoke(archive_failure=fail_call)
                self.assertIsNotNone(error)
                state = report['stages']['offline_package']
                self.assertEqual(state['status'], 'failed')
                self.assertIn('fixture archive write/verification failure', state['error'])
                self.assertNotIn('sha256', state)

    def test_record_cannot_bypass_compile_pe_source_or_staging_failures(self):
        for failure, stage in (('compile_link', 'compile_link'), ('compile_link_exception', 'compile_link'),
                               ('pe_machine', 'pe'), ('pe_second', 'pe'), ('pe_read', 'pe'),
                               ('source_metadata', 'source_metadata'), ('source_unchanged', 'source_unchanged'),
                               ('staging', 'staging')):
            with self.subTest(failure=failure):
                report, _, error, calls = self.invoke(failure, policy='record')
                self.assertIsNotNone(error)
                self.assertEqual(report['stages'][stage]['status'], 'failed')
                self.assertEqual(report['stages']['offline_package']['status'], 'not_run')
                self.assertEqual(report['stages']['inf_syntax']['status'], 'not_run')
                self.assertFalse(any('/v' in command for command in calls))
                if failure in ('pe_second', 'pe_read'):
                    self.assertIn('USBPcap.sys', report['stages']['pe']['images'])
                if failure == 'compile_link_exception':
                    self.assertIn('/p:SignMode=Off', report['stages']['compile_link']['command'])

    def test_informational_api_failure_does_not_change_strict_policy(self):
        report, result, error, _ = self.invoke('api_universal_diagnostic')
        self.assertIsNone(error)
        self.assertEqual(result, 0)
        self.assertEqual(report['stages']['api_universal_diagnostic']['status'], 'failed')
        self.assertEqual(report['validation_failures'], [])
        self.assertEqual(report['stages']['offline_package']['status'], 'passed')

    def test_api_extractor_command_uses_existing_directory_not_executable(self):
        report, result, error, calls = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(result, 0)
        command = report['stages']['api_universal_diagnostic']['command']
        self.assertIn(command, calls)
        arguments = [arg for arg in command if arg.startswith('-ApiExtractorExePath:')]
        self.assertEqual(arguments, ['-ApiExtractorExePath:' + str(self.root / 'api-extractor-tools')])
        folder = Path(arguments[0].split(':', 1)[1])
        self.assertTrue(folder.is_dir())
        self.assertTrue((folder / 'AitStatic.exe').is_file())

    def test_real_malformed_pe_is_fatal_under_both_policies(self):
        for policy in ('strict', 'record'):
            for name, data in malformed_pe_fixtures().items():
                with self.subTest(policy=policy, mutation=name):
                    report, _, error, calls = self.invoke(policy=policy, driver_bytes=data)
                    self.assertIsInstance(error, ValueError)
                    self.assertEqual(report['stages']['compile_link']['status'], 'passed')
                    self.assertEqual(report['stages']['pe']['status'], 'failed')
                    self.assertEqual(report['stages']['pe']['current_image'], 'USBPcap.sys')
                    for key in ('staging', 'inf_syntax', 'offline_package'):
                        self.assertEqual(report['stages'][key]['status'], 'not_run')
                    self.assertFalse(any('/v' in command for command in calls))
                    self.assertFalse((self.root / 'artifacts/package/ARM64/USBPcap-ARM64-Release-UNSIGNED-OFFLINE.zip').exists())

    def test_compile_failure_is_fatal_under_both_policies(self):
        for policy in ('strict', 'record'):
            with self.subTest(policy=policy):
                report, _, error, _ = self.invoke('compile_link', policy=policy)
                self.assertIsNotNone(error)
                self.assertEqual(report['stages']['compile_link']['status'], 'failed')
                self.assertEqual(report['stages']['pe']['status'], 'not_run')
                self.assertEqual(report['stages']['offline_package']['status'], 'not_run')

    def test_real_target_gate_failures_are_fatal_under_both_policies(self):
        fixtures = {'kernel_not_page_aligned': low_alignment_pe_fixture(),
                    'kernel_user_mode_import': pe_fixture(imports=('ntoskrnl.exe', 'kernel32.dll')),
                    'kernel_no_imports': pe_fixture(imports=())}
        for name, offset, fmt, value in (
                ('wrong_machine', PE_OFFSET + 4, '<H', 0x8664),
                ('wrong_subsystem', PE_OPT + 68, '<H', 2),
                ('missing_nx', PE_OPT + 70, '<H', 0),
                ('writable_executable', PE_SECTIONS + 36, '<I', 0xE0000020)):
            data = pe_fixture()
            struct.pack_into(fmt, data, offset, value)
            fixtures[name] = data
        data = pe_fixture()
        data.extend(struct.pack('<IHH', 8, 0x200, 2))
        struct.pack_into('<II', data, PE_OPT + 112 + 4 * 8, 0x600, 8)
        fixtures['embedded_certificate'] = data
        data = pe_fixture()
        struct.pack_into('<II', data, PE_OPT + 112 + 14 * 8, 0x2080, 72)
        fixtures['clr_present'] = data
        for policy in ('strict', 'record'):
            for name, data in fixtures.items():
                with self.subTest(policy=policy, mutation=name):
                    # Prove this is the inspection gate, not a broken fixture.
                    self.module.pe_metadata(data)
                    report, _, error, _ = self.invoke(policy=policy, driver_bytes=data)
                    self.assertIsInstance(error, RuntimeError)
                    self.assertEqual(report['stages']['pe']['status'], 'failed')
                    self.assertIn('USBPcap.sys', report['stages']['pe']['images'])
                    self.assertEqual(report['stages']['staging']['status'], 'not_run')
                    self.assertEqual(report['stages']['offline_package']['status'], 'not_run')

    def test_archive_failure_does_not_publish_or_replace_an_existing_zip(self):
        archive = self.root / 'artifacts/package/ARM64/USBPcap-ARM64-Release-UNSIGNED-OFFLINE.zip'
        for existing in (False, True):
            if existing:
                archive.parent.mkdir(parents=True, exist_ok=True)
                archive.write_bytes(b'PREVIOUS TEXT FIXTURE: NOT A ZIP')
            for failure in (1, 2, 'final_integrity'):
                with self.subTest(existing=existing, failure=failure):
                    report, _, error, _ = self.invoke(archive_failure=failure)
                    self.assertIsNotNone(error)
                    state = report['stages']['offline_package']
                    self.assertEqual(state['status'], 'failed')
                    self.assertFalse(state['published'])
                    verification = 'candidate_archive_verification' if failure == 1 else 'final_archive_verification'
                    self.assertEqual(state[verification]['status'], 'failed')
                    self.assertFalse(archive.with_suffix('.zip.tmp').exists())
                    if existing:
                        self.assertEqual(archive.read_bytes(), b'PREVIOUS TEXT FIXTURE: NOT A ZIP')
                    else:
                        self.assertFalse(archive.exists())

    def test_run_output_survives_log_write_failure(self):
        m = self.module
        log = self.root / 'broken.log'
        original_write = Path.write_text
        def write(path, *args, **kwargs):
            if path == log:
                raise OSError('fixture log write failed')
            return original_write(path, *args, **kwargs)
        args = SimpleNamespace(configuration='Release', validation_policy='strict')
        with mock.patch.object(m, 'ROOT', self.root), contextlib.redirect_stdout(io.StringIO()):
            report = m.ValidationReport(self.root / 'validation.json', args)
            completed = SimpleNamespace(stdout='fixture completed command output', returncode=7)
            with mock.patch.object(m.subprocess, 'run', return_value=completed), \
                    mock.patch.object(Path, 'write_text', autospec=True, side_effect=write):
                with self.assertRaisesRegex(OSError, 'fixture log write failed'):
                    report.command('compile_link', ['fixture-tool'], log)
            persisted = json.loads(report.path.read_text())
        state = persisted['stages']['compile_link']
        self.assertEqual(state['status'], 'failed')
        self.assertEqual(state['exit_code'], 7)
        self.assertEqual(state['output'], 'fixture completed command output')
        self.assertEqual(state['command'], ['fixture-tool'])

    def test_report_is_saved_before_invocation_and_between_commands(self):
        m = self.module
        args = SimpleNamespace(configuration='Release', validation_policy='strict')
        with mock.patch.object(m, 'ROOT', self.root):
            report = m.ValidationReport(self.root / 'validation.json', args)
            initial = json.loads(report.path.read_text())
            self.assertTrue(all(s['status'] == 'not_run' for s in initial['stages'].values()))
            def run(command, log, env):
                saved = json.loads(report.path.read_text())
                stage = str(command[0])
                self.assertTrue(saved['stages'][stage]['attempted'])
                self.assertEqual(saved['stages'][stage]['command'], [stage])
                if stage == 'inf_desktop_signability':
                    self.assertEqual(saved['stages']['inf_syntax']['status'], 'passed')
                    self.assertEqual(saved['stages']['inf_syntax']['output'], 'fixture prior output')
                return {'status': 'passed', 'exit_code': 0, 'output': 'fixture prior output'}
            with mock.patch.object(m, 'run', side_effect=run):
                for name in ('inf_syntax', 'inf_desktop_signability'):
                    report.command(name, [name], self.root / (name + '.log'))

    def test_archive_verification_checks_manifest_digests(self):
        stage = self.root / 'stage'
        stage.mkdir()
        (stage / 'OFFLINE-ONLY.txt').write_text('UNIT TEST TEXT ONLY')
        (stage / 'SHA256SUMS').write_text('0' * 64 + '  OFFLINE-ONLY.txt\n')
        with self.assertRaisesRegex(RuntimeError, 'SHA256SUMS mismatch'):
            self.module.archive_package(stage, self.root / 'bad.zip')

    def test_static_and_check_only_reports_do_not_claim_compilation(self):
        for flag in ('--static-only', '--check-only'):
            with self.subTest(flag=flag):
                report, result, error, _ = self.invoke(flags=(flag,))
                self.assertIsNone(error)
                self.assertEqual(result, 0)
                self.assertEqual(report['stages']['static']['status'], 'passed')
                self.assertEqual(report['stages']['compile_link']['status'], 'not_run')


def actual_driver_libraries():
    return set(x.lower() for x in re.findall(r'\b([\w]+\.lib)', ET.tostring(project('USBPcapDriver').getroot(), encoding='unicode')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
