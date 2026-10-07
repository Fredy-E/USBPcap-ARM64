"""Source-contract regressions only: these do NOT qualify a live kernel driver."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(path, name):
    source = (ROOT / path).read_text()
    mask = re.sub(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*',
                  lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', mask)
    if match is None:
        raise AssertionError('Missing function ' + name)
    start = mask.index('{', match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (mask[end] == '{') - (mask[end] == '}')
        end += 1
    return source[match.start():end]


class HardeningContracts(unittest.TestCase):
    def test_both_teardown_paths_free_before_final_device_delete(self):
        for name in ('DkDetachAndDeleteHubFilt', 'DkDetachAndDeleteTgt'):
            with self.subTest(name=name):
                body = function('USBPcapDriver/USBPcapFilterManager.c', name)
                self.assertLess(body.index('USBPcapFreeDeviceData('), body.index('IoDeleteDevice('))
                self.assertNotIn('pDevExt->', body[body.index('IoDeleteDevice('):])

    def test_attachment_failure_detaches_before_free(self):
        body = function('USBPcapDriver/USBPcapFilterManager.c', 'AddDevice')
        failure = body[body.index('EndFunc:'):]
        self.assertIn('IoDetachDevice(', failure)
        self.assertLess(failure.index('IoDetachDevice('), failure.index('USBPcapFreeDeviceData('))

    def test_root_hub_initializing_flag_is_cleared_only_after_control_creation(self):
        body = function('USBPcapDriver/USBPcapFilterManager.c', 'AddDevice')
        self.assertLess(body.index('USBPcapCreateRootHubControlDevice('), body.index('~DO_DEVICE_INITIALIZING'))
        self.assertIn('USHORT                 id = 0;', body)

    def test_table_allocation_failures_propagate(self):
        body = function('USBPcapDriver/USBPcapFilterManager.c', 'USBPcapAllocateDeviceData')
        self.assertRegex(body, re.compile(r'endpointTable == NULL.*?\|\|', re.S))
        self.assertIn('pDeviceData->URBIrpTable == NULL', body)
        self.assertIn('status = STATUS_INSUFFICIENT_RESOURCES;', body[body.index('USBPcapInitializeEndpointTable('):])

    def test_all_capture_mdl_mappings_are_non_executable(self):
        for file in ('USBPcapBuffer.c', 'USBPcapURB.c'):
            source = (ROOT / 'USBPcapDriver' / file).read_text()
            calls = re.findall(r'MmGetSystemAddressForMdlSafe\([^;]*?\);', source, re.S)
            self.assertTrue(calls)
            self.assertTrue(all('MdlMappingNoExecute' in call for call in calls))

    def test_interface_bounds_checked_before_header_and_pipe_access(self):
        body = function('USBPcapDriver/USBPcapURB.c', 'USBPcapParseInterfaceInformation')
        self.assertIn('offsetof(USBD_INTERFACE_INFORMATION, Pipes)', body)
        self.assertLess(body.index('interfaces_len <'), body.index('pInterface->Length'))
        self.assertIn('pInterface->NumberOfPipes >', body)
        self.assertRegex(body, r'/\s*sizeof\(USBD_PIPE_INFORMATION\)')
        self.assertNotIn('(pInterface->NumberOfPipes - 1) *', body)

    def test_packet_payload_count_does_not_include_pcap_record_header(self):
        body = function('USBPcapDriver/USBPcapBuffer.c', 'USBPcapBufferStorePacket')
        self.assertIn('UINT32 bytesMissing = bytes - header->headerLen;', body)
        self.assertNotIn('bytes - (sizeof(pcaprec_hdr_t) + header->headerLen)', body)
        self.assertIn('header->dataLength > MAXULONG - header->headerLen', body)

    def test_configuration_descriptor_replacement_checks_allocation_and_locks(self):
        source = (ROOT / 'USBPcapDriver/USBPcapURB.c').read_text()
        block = source[source.index('/* Store the configuration information for later use */'):]
        block = block[:block.index('case URB_FUNCTION_SELECT_INTERFACE:')]
        self.assertIn('newDescriptor != NULL', block)
        self.assertIn('KeAcquireSpinLock(&pDeviceData->tablesSpinLock', block)
        self.assertIn('oldDescriptor = pDeviceData->descriptor;', block)
        self.assertLess(block.index('newDescriptor != NULL'), block.index('RtlCopyMemory('))
        self.assertLess(block.index('pDeviceData->descriptor = newDescriptor;'), block.index('ExFreePool('))


    def test_target_parent_lock_is_acquired_before_device_data_and_balanced_on_failure(self):
        body = function('USBPcapDriver/USBPcapFilterManager.c', 'DkCreateAndAttachTgt')
        self.assertLess(body.index('ntStat = IoAcquireRemoveLock('), body.index('USBPcapAllocateDeviceData('))
        failure = body[body.index('EndAttDev:'):]
        self.assertLess(failure.index('USBPcapFreeDeviceData('), failure.index('IoReleaseRemoveLock('))
        self.assertLess(failure.index('IoReleaseRemoveLock('), failure.index('IoDeleteDevice('))

    def test_allocation_initialization_precedes_failure_cleanup(self):
        body = function('USBPcapDriver/USBPcapFilterManager.c', 'USBPcapAllocateDeviceData')
        self.assertLess(body.index('RtlZeroMemory(pDeviceData,'), body.index('USBPcapInitializeEndpointTable('))
        self.assertIn('RtlZeroMemory(pDeviceData->pRootData,', body)

    def test_typed_urb_guard_precedes_typed_switch_analysis(self):
        body = function('USBPcapDriver/USBPcapURB.c', 'USBPcapAnalyzeURB')
        self.assertLess(body.index('header->Length < requiredLength'), body.index('/* Following URBs are always analyzed */'))
        for kind in ('_URB_CONTROL_TRANSFER', '_URB_CONTROL_TRANSFER_EX',
                     '_URB_CONTROL_DESCRIPTOR_REQUEST', '_URB_CONTROL_GET_STATUS_REQUEST',
                     '_URB_CONTROL_VENDOR_OR_CLASS_REQUEST', '_URB_BULK_OR_INTERRUPT_TRANSFER',
                     '_URB_PIPE_REQUEST', '_URB_GET_CURRENT_FRAME_NUMBER'):
            self.assertIn('sizeof(struct ' + kind + ')', body)

    def test_iso_guards_precede_packet_copy_and_pointer_arithmetic(self):
        source = function('USBPcapDriver/USBPcapURB.c', 'USBPcapAnalyzeURB')
        block = source[source.rindex('case URB_FUNCTION_ISOCH_TRANSFER:'):]
        self.assertLess(block.index('transfer->NumberOfPackets == 0'), block.index('/* Copy the packet headers untouched */'))
        self.assertRegex(block, r'/\s*sizeof\(USBD_ISO_PACKET_DESCRIPTOR\)')
        self.assertLess(block.index('transferBuffer == NULL'), block.index('&transferBuffer['))
        self.assertLess(block.index('transfer->TransferBufferLength - compactedLength'),
                        block.index('compactedLength += transfer->IsoPacket[i].Length'))

    def test_select_interface_copies_descriptor_fields_while_locked(self):
        source = function('USBPcapDriver/USBPcapURB.c', 'USBPcapAnalyzeURB')
        block = source[source.rindex('case URB_FUNCTION_SELECT_INTERFACE:'):]
        block = block[:block.index('case URB_FUNCTION_CONTROL_TRANSFER:')]
        self.assertLess(block.index('KeAcquireSpinLock('), block.index('USBD_ParseConfigurationDescriptorEx('))
        copied = block.index('alternateSetting = intDescriptor->bAlternateSetting;')
        released = block.index('KeReleaseSpinLock(', copied)
        self.assertNotIn('intDescriptor->', block[released:])

    def test_completion_tracking_retired_before_null_short_and_typed_urb_guards(self):
        body = function('USBPcapDriver/USBPcapURB.c', 'USBPcapAnalyzeURB')
        retired = body.index('USBPcapObtainURBIRPInfo(')
        self.assertLess(body.index('pDeviceData == NULL'), retired)
        self.assertLess(retired, body.index('pUrb == NULL'))
        self.assertLess(retired, body.index('header->Length < requiredLength'))

    def test_iso_packet_bounds_use_mdl_capacity_only_for_chosen_mdl_buffer(self):
        body = function('USBPcapDriver/USBPcapURB.c', 'USBPcapAnalyzeURB')
        block = body[body.rindex('case URB_FUNCTION_ISOCH_TRANSFER:'):]
        self.assertIn('ULONG                         bufferCapacity;', block)
        self.assertIn('transfer->TransferBuffer == NULL && transfer->TransferBufferMDL != NULL', block)
        self.assertIn('bufferCapacity = MmGetMdlByteCount(transfer->TransferBufferMDL);', block)
        self.assertIn('bufferCapacity - transfer->IsoPacket[i].Offset', block)
        self.assertIn('transfer->TransferBufferLength - compactedLength', block)

    def test_descriptor_chain_validates_forward_progress_and_remaining_span(self):
        body = function('USBPcapDriver/USBPcapURB.c', 'USBPcapValidConfigurationDescriptor')
        self.assertIn('total - offset < 2', body)
        self.assertIn('length < 2 || length > total - offset', body)
        self.assertLess(body.index('length < 2'), body.index('offset += length'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
