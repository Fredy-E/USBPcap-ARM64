/*
 * Copyright (c) 2013-2019 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef USBPCAP_QUEUE_H
#define USBPCAP_QUEUE_H

#include "Wdm.h"
#include "include\USBPcap.h"

__drv_raisesIRQL(DISPATCH_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
VOID DkCsqAcquireLock(__in PIO_CSQ pCsq, __out __drv_out_deref(__drv_savesIRQL) PKIRQL pKIrql);

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID DkCsqReleaseLock(__in PIO_CSQ pCsq, __in __drv_in(__drv_restoresIRQL) KIRQL kIrql);

IO_CSQ_INSERT_IRP_EX DkCsqInsertIrp;
IO_CSQ_REMOVE_IRP DkCsqRemoveIrp;
IO_CSQ_PEEK_NEXT_IRP DkCsqPeekNextIrp;
IO_CSQ_COMPLETE_CANCELED_IRP DkCsqCompleteCanceledIrp;

VOID DkCsqCleanUpQueue(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID DkCsqDrainQueue(PIO_CSQ pCsq, PFILE_OBJECT fileObject);
VOID DkCsqCompleteRead(PIO_CSQ pCsq, PIRP pIrp, NTSTATUS status, ULONG_PTR bytes);

typedef struct _USBPCAP_READ_CONTEXT {
    PVOID buffer;
    UINT32 length;
    UINT32 bytes;
    NTSTATUS status;
    /* True only when the atomic callback observes no data and queues the IRP.
     * Read after insertion without touching a possibly cancelled/freed IRP. */
    BOOLEAN queued;
} USBPCAP_READ_CONTEXT, *PUSBPCAP_READ_CONTEXT;

/* Called by the insert callback with csqSpinLock held. */
NTSTATUS USBPcapBufferReadOrQueue(PIO_CSQ pCsq, PIRP pIrp,
                                 PUSBPCAP_READ_CONTEXT context);

#endif /* USBPCAP_QUEUE_H */

