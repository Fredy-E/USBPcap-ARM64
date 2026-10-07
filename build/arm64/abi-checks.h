/* Compile-time wire/IOCTL ABI checks; included by both ARM64 projects. */
#ifndef USBPCAP_ARM64_ABI_CHECKS_H
#define USBPCAP_ARM64_ABI_CHECKS_H
#ifndef _M_ARM64
#error Native ARM64 compiler required (ARM64EC is not a kernel target)
#endif
#ifdef _M_ARM64EC
#error ARM64EC is not supported
#endif
#ifdef USBPCAP_KERNEL_BUILD
#ifdef USBPCAP_DEFINE_GUIDS
/* The forced ABI include must preserve this source's original INITGUID intent. */
#include <initguid.h>
#endif
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif
#include "USBPcap.h"
C_ASSERT(sizeof(void *) == 8);
C_ASSERT(sizeof(USBPCAP_IOCTL_SIZE) == 4);
C_ASSERT(sizeof(USBPCAP_ADDRESS_FILTER) == 17);
C_ASSERT(sizeof(pcap_hdr_t) == 24);
C_ASSERT(sizeof(pcaprec_hdr_t) == 16);
C_ASSERT(sizeof(USBPCAP_BUFFER_PACKET_HEADER) == 27);
C_ASSERT(FIELD_OFFSET(USBPCAP_BUFFER_PACKET_HEADER, irpId) == 2);
C_ASSERT(FIELD_OFFSET(USBPCAP_BUFFER_PACKET_HEADER, dataLength) == 23);
C_ASSERT(sizeof(USBPCAP_BUFFER_CONTROL_HEADER) == 28);
C_ASSERT(sizeof(USBPCAP_BUFFER_ISO_PACKET) == 12);
C_ASSERT(FIELD_OFFSET(USBPCAP_BUFFER_ISOCH_HEADER, packet) == 39);
#endif
