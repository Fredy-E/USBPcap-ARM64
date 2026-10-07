/*
 * Copyright (c) 2013-2019 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "USBPcapMain.h"
#include "USBPcapBuffer.h"
#include "USBPcapHelperFunctions.h"

#define USBPCAP_BUFFER_TAG  (ULONG)'ffuB'

__inline static UINT32
USBPcapGetBufferFree(PUSBPCAP_ROOTHUB_DATA pData)
{
    if (pData->buffer == NULL)
    {
        /* There is no buffer, nothing can be written */
        return 0;
    }
    else if (pData->readOffset == pData->writeOffset)
    {
        /* readOffset is equal to writeOffset when buffer is empty
         *
         * At max, we can write bufferSize - 1 bytes of data
         */
        return pData->bufferSize - 1;
    }
    else if (pData->readOffset > pData->writeOffset)
    {
        /* readOffset is bigger than writeOffset when:
         * XXXXXXXW.............RXXXXXXX
         *
         * where:
         *   X is data to be read
         *   . is free data
         *   R is readOffset (first byte to be read)
         *   W is writeOffset (first empty byte)
         */

        return pData->readOffset - pData->writeOffset - 1;
    }
    else
    {
        /* readOffset is lower than writeOffset when:
         * ........RXXXXXXXXXXW.........
         */

        return pData->bufferSize - pData->writeOffset +
               pData->readOffset - 1;
    }
}

__inline static UINT32
USBPcapGetBufferAllocated(PUSBPCAP_ROOTHUB_DATA pData)
{
    if (pData->readOffset == pData->writeOffset)
    {
        /* readOffset is equal to writeOffset when buffer is empty
         */
        return 0;
    }
    else if (pData->readOffset > pData->writeOffset)
    {
        /* readOffset is bigger than writeOffset when:
         * XXXXXXXW.............RXXXXXXX
         */

        return pData->bufferSize - pData->readOffset +
               pData->writeOffset;
    }
    else
    {
        /* readOffset is lower than writeOffset when:
         * ........RXXXXXXXXXXW.........
         */

        return pData->writeOffset - pData->readOffset;
    }
}

__inline static void
USBPcapBufferWriteUnsafe(PUSBPCAP_ROOTHUB_DATA pData,
                         PVOID data,
                         UINT32 length)
{
    PCHAR buffer = (PCHAR)pData->buffer;

    if (pData->bufferSize - pData->writeOffset >= length)
    {
        /* We can write all data without looping */
        RtlCopyMemory((PVOID)&buffer[pData->writeOffset],
                      data,
                      (SIZE_T)length);
        pData->writeOffset += length;
        pData->writeOffset %= pData->bufferSize;
    }
    else
    {
        /* We need to loop */
        PCHAR origData = (PCHAR)data;
        UINT32 tmp;

        /* First copy */
        tmp = pData->bufferSize - pData->writeOffset;
        RtlCopyMemory((PVOID)&buffer[pData->writeOffset],
                      data,
                      (SIZE_T)tmp);

        /* Second copy */
        RtlCopyMemory(pData->buffer, /* Write at beginning of buffer */
                      (PVOID)&origData[tmp],
                      length - tmp);

        pData->writeOffset = length - tmp;
    }
}

/*
 * Writes data to buffer.
 *
 * Caller must have acquired buffer spin lock.
 */
static NTSTATUS USBPcapBufferWrite(PUSBPCAP_ROOTHUB_DATA pData,
                                   PVOID data,
                                   UINT32 length)
{
    if (length == 0)
    {
        DkDbgStr("Cannot write empty data.");
        return STATUS_INVALID_PARAMETER;
    }

    if (USBPcapGetBufferFree(pData) < length)
    {
        DkDbgStr("No free space left.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    USBPcapBufferWriteUnsafe(pData, data, length);
    return STATUS_SUCCESS;
}

/*
 * Reads data from circular buffer.
 *
 * Retruns number of bytes read.
 */
static UINT32 USBPcapBufferRead(PUSBPCAP_ROOTHUB_DATA pData,
                                PVOID destBuffer,
                                UINT32 destBufferSize)
{
    UINT32 available;
    UINT32 toRead;

    PCHAR srcBuffer = (PCHAR)pData->buffer;

    available = USBPcapGetBufferAllocated(pData);

    /* No data to be read or empty destination buffer */
    if (available == 0 || destBufferSize == 0)
    {
        return 0;
    }

    /* Calculate how many bytes will fit into buffer */
    if (available > destBufferSize)
    {
        toRead = destBufferSize;
    }
    else
    {
        toRead = available;
    }

    if (pData->writeOffset > pData->readOffset)
    {
        /* Simply copy the contiguous data */
        RtlCopyMemory(destBuffer,
                      (PVOID)&srcBuffer[pData->readOffset],
                      (SIZE_T)toRead);

        pData->readOffset += toRead;
        pData->readOffset %= pData->bufferSize;
    }
    else
    {
        UINT32 tmp;
        tmp = pData->bufferSize - pData->readOffset;

        if (tmp >= toRead)
        {
            /* Copy contiguous data */
            RtlCopyMemory(destBuffer,
                          (PVOID)&srcBuffer[pData->readOffset],
                          (SIZE_T)toRead);

            pData->readOffset += toRead;
            pData->readOffset %= pData->bufferSize;
        }
        else
        {
            PCHAR dstBuffer = (PCHAR)destBuffer;
            /* Copy non-contiguous data */

            /* First copy */
            RtlCopyMemory(destBuffer,
                          (PVOID)&srcBuffer[pData->readOffset],
                          (SIZE_T)tmp);

            /* Second copy */
            RtlCopyMemory((PVOID)&dstBuffer[tmp],
                          (PVOID)srcBuffer,
                          (SIZE_T)toRead - tmp);

            pData->readOffset = toRead - tmp;
        }
    }

    return toRead;
}


/*
 * Writes global PCAP header to buffer.
 * Caller must have acquired buffer spin lock.
 */
__inline static VOID
USBPcapWriteGlobalHeader(PUSBPCAP_ROOTHUB_DATA pData)
{
    pcap_hdr_t header;

    header.magic_number = 0xA1B2C3D4;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0 /* Assume UTC */;
    header.sigfigs = 0;
    header.snaplen = pData->snaplen;
    header.network = DLT_USBPCAP;

    ASSERT (USBPcapGetBufferFree(pData) >= sizeof(header));

    USBPcapBufferWrite(pData, (PVOID)&header, sizeof(header));
}

NTSTATUS USBPcapSetUpBuffer(PUSBPCAP_ROOTHUB_DATA pData,
                            UINT32 bytes)
{
    NTSTATUS  status;
    KIRQL     irql;
    PVOID     buffer;

    /* Minimum buffer size is 4 KiB, maximum 128 MiB */
    if (bytes < 4096 || bytes > 134217728)
    {
        return STATUS_INVALID_PARAMETER;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   (SIZE_T) bytes,
                                   USBPCAP_BUFFER_TAG);

    if (buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    KeAcquireSpinLock(&pData->bufferLock, &irql);
    if (pData->buffer == NULL)
    {
        pData->buffer = buffer;
        pData->bufferSize = bytes;
        pData->readOffset = 0;
        pData->writeOffset = 0;
        USBPcapWriteGlobalHeader(pData);
        DkDbgVal("Created new buffer", bytes);
    }
    else
    {
        UINT32 allocated = USBPcapGetBufferAllocated(pData);

        if (allocated >= bytes)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            ExFreePool(buffer);
        }
        else
        {
            /* Copy (if any) unread data to new buffer */
            if (allocated > 0)
            {
                USBPcapBufferRead(pData, buffer, bytes);
            }

            /* Free the old buffer */
            ExFreePool(pData->buffer);
            pData->buffer = buffer;
            pData->bufferSize = bytes;
            pData->readOffset = 0;
            pData->writeOffset = allocated;
        }
    }

    KeReleaseSpinLock(&pData->bufferLock, irql);
    return status;
}

NTSTATUS USBPcapSetSnaplenSize(PUSBPCAP_ROOTHUB_DATA pData,
                               UINT32 bytes)
{
    NTSTATUS  status;
    KIRQL     irql;

    if (bytes == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_SUCCESS;
    KeAcquireSpinLock(&pData->bufferLock, &irql);
    if (pData->buffer != NULL)
    {
        status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        pData->snaplen = bytes;
    }

    KeReleaseSpinLock(&pData->bufferLock, irql);
    return status;
}

/*
 * If there is buffer allocated for given control device, frees all
 * memory allocated to it, otherwise does nothing.
 */
VOID USBPcapBufferRemoveBuffer(PDEVICE_EXTENSION pDevExt)
{
    PDEVICE_EXTENSION      pRootExt;
    PUSBPCAP_ROOTHUB_DATA  pData;
    KIRQL                  irql;

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    pRootExt = (PDEVICE_EXTENSION)pDevExt->context.control.pRootHubObject->DeviceExtension;
    pData = pRootExt->context.usb.pDeviceData->pRootData;

    /* Buffer found - free it */
    KeAcquireSpinLock(&pData->bufferLock, &irql);
    pData->readOffset = 0;
    pData->writeOffset = 0;
    if (pData->buffer != NULL)
    {
        ExFreePool((PVOID)pData->buffer);
    }
    pData->buffer = NULL;
    pData->bufferSize = 0;
    KeReleaseSpinLock(&pData->bufferLock, irql);
}

/*
 * If there is buffer allocated for given control device, writes global
 * PCAP header to the buffer, otherwise does nothing.
 */
VOID USBPcapBufferInitializeBuffer(PDEVICE_EXTENSION pDevExt)
{
    PDEVICE_EXTENSION      pRootExt;
    PUSBPCAP_ROOTHUB_DATA  pData;
    KIRQL                  irql;

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    pRootExt = (PDEVICE_EXTENSION)pDevExt->context.control.pRootHubObject->DeviceExtension;
    pData = pRootExt->context.usb.pDeviceData->pRootData;

    /* Buffer found - reset all data and write global PCAP header */
    KeAcquireSpinLock(&pData->bufferLock, &irql);
    if (pData->buffer != NULL)
    {
        pData->readOffset = 0;
        pData->writeOffset = 0;
        USBPcapWriteGlobalHeader(pData);
    }
    KeReleaseSpinLock(&pData->bufferLock, irql);
}

NTSTATUS USBPcapBufferHandleReadIrp(PIRP pIrp,
                                    PDEVICE_EXTENSION pDevExt,
                                    PUINT32 pBytesRead)
{
    PVOID                  buffer;
    UINT32                 bufferLength;
    NTSTATUS               status;
    USBPCAP_READ_CONTEXT   context;
    PIO_STACK_LOCATION     pStack = NULL;

    pStack = IoGetCurrentIrpStackLocation(pIrp);

    *pBytesRead = 0;

    if (pStack->Parameters.Read.Length == 0)
    {
        return STATUS_SUCCESS;
    }


    /*
     * Since control device has DO_DIRECT_IO bit set the MDL is already
     * probed and locked
     */
    if (pIrp->MdlAddress == NULL ||
        pStack->Parameters.Read.Length > MmGetMdlByteCount(pIrp->MdlAddress))
    {
        return STATUS_INVALID_PARAMETER;
    }
    buffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress,
                                          NormalPagePriority | MdlMappingNoExecute);

    if (buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        bufferLength = pStack->Parameters.Read.Length;
    }

    /* Dispatch retains its original acquisition through return. Completion
     * owns the extra acquisition, including immediate CSQ cancellation. */
    status = IoAcquireRemoveLock(&pDevExt->removeLock, pIrp);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    context.buffer = buffer;
    context.length = bufferLength;
    context.bytes = 0;
    context.status = STATUS_SUCCESS;
    context.queued = FALSE;
    IoMarkIrpPending(pIrp);
    status = IoCsqInsertIrpEx(&pDevExt->context.control.ioCsq,
                             pIrp, NULL, &context);
    if (!NT_SUCCESS(status))
    {
        /* Rejected inserts remain ours. Once marked, return pending even
         * for synchronous data; never touch IRP after successful insertion. */
        DkCsqCompleteRead(&pDevExt->context.control.ioCsq, pIrp,
                          context.status, context.bytes);
    }
    return STATUS_PENDING;
}

/* Called with CSQ lock held; CSQ -> bufferLock is the only nested order.
 * The atomic read-or-queue decision prevents a lost producer wakeup. */
NTSTATUS USBPcapBufferReadOrQueue(PIO_CSQ pCsq, PIRP pIrp,
                                 PUSBPCAP_READ_CONTEXT context)
{
    PDEVICE_EXTENSION ext = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                              context.control.ioCsq);
    PDEVICE_EXTENSION root;
    PUSBPCAP_ROOTHUB_DATA data;
    KIRQL irql;
    context->queued = FALSE;
    if (ext->context.control.removing || ext->context.control.captureClosing)
    {
        context->status = STATUS_CANCELLED;
        return STATUS_UNSUCCESSFUL;
    }
    root = (PDEVICE_EXTENSION)ext->context.control.pRootHubObject->DeviceExtension;
    data = root->context.usb.pDeviceData->pRootData;
    KeAcquireSpinLock(&data->bufferLock, &irql);
    if (data->buffer == NULL)
    {
        context->status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        context->bytes = USBPcapBufferRead(data, context->buffer, context->length);
        if (context->bytes == 0)
        {
            InsertTailList(&ext->context.control.lePendIrp,
                            &pIrp->Tail.Overlay.ListEntry);
            context->queued = TRUE;
            KeReleaseSpinLock(&data->bufferLock, irql);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&data->bufferLock, irql);
    return STATUS_UNSUCCESSFUL; /* caller completes outside locks */
}

/* Caller retains one transient control remove-lock reference through the
 * entire drain, with no driver lock held. Each dequeued read already owns
 * its separate completion reference. Keep the private void API unchanged. */
static void USBPcapBufferCompletePendedReadIrp(PUSBPCAP_ROOTHUB_DATA pRootData,
                                              PDEVICE_EXTENSION pControlExt)
{
    PIRP pIrp;
    PVOID buffer;
    UINT32 bufferLength;
    KIRQL irql;
    BOOLEAN available;
    USBPCAP_READ_CONTEXT context;
    NTSTATUS insertStatus;

    ASSERT(pControlExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    for (;;)
    {
        /* A hint only: another reader may steal these bytes after unlock.
         * Never call CSQ while holding bufferLock (CSQ -> buffer only). */
        KeAcquireSpinLock(&pRootData->bufferLock, &irql);
        available = pRootData->buffer != NULL &&
                    USBPcapGetBufferAllocated(pRootData) != 0;
        KeReleaseSpinLock(&pRootData->bufferLock, irql);
        if (!available)
        {
            return;
        }
        pIrp = IoCsqRemoveNextIrp(&pControlExt->context.control.ioCsq, NULL);
        if (pIrp == NULL)
        {
            return;
        }

        /* Only nonzero, validated direct-I/O reads enter the queue. Treat
         * an unavailable mapping or invalid destination as failure, not
         * successful zero-byte progress. Complete outside ALL driver locks. */
        buffer = (pIrp->MdlAddress == NULL) ? NULL :
            MmGetSystemAddressForMdlSafe(pIrp->MdlAddress,
                                        NormalPagePriority | MdlMappingNoExecute);
        if (buffer == NULL)
        {
            DkCsqCompleteRead(&pControlExt->context.control.ioCsq, pIrp,
                              STATUS_INSUFFICIENT_RESOURCES, 0);
            continue;
        }
        bufferLength = min(MmGetMdlByteCount(pIrp->MdlAddress),
                           IoGetCurrentIrpStackLocation(pIrp)->Parameters.Read.Length);
        if (bufferLength == 0)
        {
            DkCsqCompleteRead(&pControlExt->context.control.ioCsq, pIrp,
                              STATUS_INVALID_PARAMETER, 0);
            continue;
        }

        /* Reuse the atomic admission/read-or-queue callback even when the
         * hint says data is available. It checks cleanup/removal under CSQ
         * lock before reading under bufferLock. No extra pending acquisition.
         * Successful insertion may cancel/complete before it returns; inspect
         * only stack context afterwards, never the transferred IRP. */
        context.buffer = buffer;
        context.length = bufferLength;
        context.bytes = 0;
        context.status = STATUS_SUCCESS;
        context.queued = FALSE;
        insertStatus = IoCsqInsertIrpEx(&pControlExt->context.control.ioCsq,
                                       pIrp, NULL, &context);
        if (!NT_SUCCESS(insertStatus))
        {
            DkCsqCompleteRead(&pControlExt->context.control.ioCsq, pIrp,
                              context.status, context.bytes);
            if (context.bytes == 0)
            {
                /* Admission closed or buffer removed; teardown drains the
                 * other reads. No manufactured successful empty completion. */
                return;
            }
        }
        else if (context.queued)
        {
            /* Actual empty-buffer outcome, not the earlier hint. A stealing
             * reader must not cause us to dequeue/requeue this IRP forever.
             * A concurrent later producer performs its own service pass. */
            return;
        }
        /* Consumed data or immediate cancellation (no callback/queue).
         * Continue until data or eligible queued readers are exhausted. */
    }
}

__inline static VOID
USBPcapInitializePcapHeader(PUSBPCAP_ROOTHUB_DATA pData,
                            LARGE_INTEGER timestamp,
                            pcaprec_hdr_t *pcapHeader,
                            UINT32 bytes)
{
    pcapHeader->ts_sec = (UINT32)(timestamp.QuadPart/10000000-11644473600);
    pcapHeader->ts_usec = (UINT32)((timestamp.QuadPart%10000000)/10);

    /* Obey the snaplen limit */
    if (bytes > pData->snaplen)
    {
        pcapHeader->incl_len = pData->snaplen;
    }
    else
    {
        pcapHeader->incl_len = bytes;
    }
    pcapHeader->orig_len = bytes;
}

/* Caller must hold bufferLock
 *
 * payloadEntries is array of USBPCAP_PAYLOAD_ENTRY with the last element being {0, NULL}
 */
static NTSTATUS
USBPcapBufferStorePacket(PUSBPCAP_ROOTHUB_DATA pRootData,
                         LARGE_INTEGER timestamp,
                         PUSBPCAP_BUFFER_PACKET_HEADER header,
                         PUSBPCAP_PAYLOAD_ENTRY payloadEntries)
{
    UINT32             bytes;
    UINT32             bytesFree;
    UINT32             tmp;
    pcaprec_hdr_t      pcapHeader;
    int                i;

    if (header == NULL || header->headerLen < sizeof(*header) ||
        header->dataLength > MAXULONG - header->headerLen)
    {
        return STATUS_INVALID_PARAMETER;
    }
    bytes = header->headerLen + header->dataLength;

    USBPcapInitializePcapHeader(pRootData, timestamp, &pcapHeader, bytes);

    /* pcapHeader.incl_len contains the number of bytes to write */
    bytes = pcapHeader.incl_len;

    /* Sanity check payload entries */
    if (bytes > header->headerLen)
    {
        UINT32 bytesMissing = bytes - header->headerLen;

        if (payloadEntries == NULL)
        {
            return STATUS_INVALID_PARAMETER;
        }

        for (i = 0; (bytesMissing > 0) && (payloadEntries[i].buffer); i++)
        {
            bytesMissing -= min(payloadEntries[i].size, bytesMissing);
        }
        if (bytesMissing > 0)
        {
            DkDbgVal("Attempted to write invalid packet. Missing %d bytes of payload.",
                     bytesMissing);
            return STATUS_INVALID_PARAMETER;
        }
    }

    bytesFree = USBPcapGetBufferFree(pRootData);

    if ((pRootData->buffer == NULL) ||
        (bytesFree < sizeof(pcaprec_hdr_t)) ||
        ((bytesFree - sizeof(pcaprec_hdr_t)) < bytes))
    {
        DkDbgStr("No enough free space left.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Write Packet Header */
    USBPcapBufferWriteUnsafe(pRootData,
                             (PVOID) &pcapHeader,
                             (UINT32) sizeof(pcaprec_hdr_t));

    /* Write USBPCAP_BUFFER_PACKET_HEADER */
    tmp = min(bytes, (UINT32)header->headerLen);
    if (tmp > 0)
    {
        USBPcapBufferWriteUnsafe(pRootData,
                                 (PVOID) header,
                                 tmp);
    }
    bytes -= tmp;

    /* Write payload entries */
    for (i = 0; (bytes > 0) && (payloadEntries[i].buffer); i++)
    {
        tmp = min(bytes, payloadEntries[i].size);
        if (tmp > 0)
        {
            USBPcapBufferWriteUnsafe(pRootData,
                                     payloadEntries[i].buffer,
                                     tmp);
        }
        bytes -= tmp;
    }

    return STATUS_SUCCESS;
}

NTSTATUS USBPcapBufferWriteTimestampedPayload(PUSBPCAP_ROOTHUB_DATA pRootData,
                                              LARGE_INTEGER timestamp,
                                              PUSBPCAP_BUFFER_PACKET_HEADER header,
                                              PUSBPCAP_PAYLOAD_ENTRY payload)
{
    KIRQL                  irql;
    NTSTATUS               status;
    PDEVICE_EXTENSION      controlExt = NULL;

    KeAcquireSpinLock(&pRootData->bufferLock, &irql);
    status = USBPcapBufferStorePacket(pRootData, timestamp, header, payload);
    if (NT_SUCCESS(status))
    {
        if (pRootData->controlDevice != NULL)
        {
            controlExt = (PDEVICE_EXTENSION)pRootData->controlDevice->DeviceExtension;
            if (!NT_SUCCESS(IoAcquireRemoveLock(&controlExt->removeLock,
                                                &controlExt)))
            {
                controlExt = NULL;
            }
        }
    }
    KeReleaseSpinLock(&pRootData->bufferLock, irql);
    if (controlExt != NULL)
    {
        USBPcapBufferCompletePendedReadIrp(pRootData, controlExt);
        IoReleaseRemoveLock(&controlExt->removeLock, &controlExt);
    }

    return status;
}

NTSTATUS USBPcapBufferWritePayload(PUSBPCAP_ROOTHUB_DATA pRootData,
                                   PUSBPCAP_BUFFER_PACKET_HEADER header,
                                   PUSBPCAP_PAYLOAD_ENTRY payload)
{
    LARGE_INTEGER timestamp = USBPcapGetCurrentTimestamp();
    return USBPcapBufferWriteTimestampedPayload(pRootData, timestamp, header, payload);
}

NTSTATUS USBPcapBufferWriteTimestampedPacket(PUSBPCAP_ROOTHUB_DATA pRootData,
                                             LARGE_INTEGER timestamp,
                                             PUSBPCAP_BUFFER_PACKET_HEADER header,
                                             PVOID buffer)
{
    USBPCAP_PAYLOAD_ENTRY  payload[2];

    payload[0].size   = header->dataLength;
    payload[0].buffer = buffer;
    payload[1].size   = 0;
    payload[1].buffer = NULL;

    return USBPcapBufferWriteTimestampedPayload(pRootData, timestamp, header, payload);
}

NTSTATUS USBPcapBufferWritePacket(PUSBPCAP_ROOTHUB_DATA pRootData,
                                  PUSBPCAP_BUFFER_PACKET_HEADER header,
                                  PVOID buffer)
{
    LARGE_INTEGER timestamp = USBPcapGetCurrentTimestamp();
    return USBPcapBufferWriteTimestampedPacket(pRootData, timestamp, header, buffer);
}
