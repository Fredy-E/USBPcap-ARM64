/*
 * Copyright (c) 2013-2019 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "USBPcapMain.h"
#include "USBPcapQueue.h"

NTSTATUS DkCsqInsertIrp(__in PIO_CSQ pCsq, __in PIRP pIrp, __in PVOID context)
{
    PDEVICE_EXTENSION   pDevExt = NULL;

    pDevExt = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                context.control.ioCsq);

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    return USBPcapBufferReadOrQueue(pCsq, pIrp,
                                    (PUSBPCAP_READ_CONTEXT)context);
}

VOID DkCsqRemoveIrp(__in PIO_CSQ pCsq, __in PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pCsq);
    RemoveEntryList(&pIrp->Tail.Overlay.ListEntry);
}

PIRP DkCsqPeekNextIrp(__in PIO_CSQ pCsq, __in PIRP pIrp, __in PVOID pCtx)
{
    PDEVICE_EXTENSION   pDevExt = NULL;
    PIRP                pNextIrp = NULL;
    PLIST_ENTRY         pNextList = NULL, pHeadList = NULL;
    PIO_STACK_LOCATION  pStack = NULL;

    pDevExt = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                context.control.ioCsq);

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    pHeadList = &pDevExt->context.control.lePendIrp;

    if (pIrp == NULL)
    {
        pNextList = pHeadList->Flink;
    }
    else
    {
        pNextList = pIrp->Tail.Overlay.ListEntry.Flink;
    }

    while (pNextList != pHeadList)
    {
        pNextIrp = CONTAINING_RECORD(pNextList, IRP, Tail.Overlay.ListEntry);
        pStack = IoGetCurrentIrpStackLocation(pNextIrp);
        if (pCtx)
        {
            if (pStack->FileObject == (PFILE_OBJECT)pCtx)
            {
                break;
            }
        }
        else
        {
            break;
        }
        pNextIrp = NULL;
        pNextList = pNextList->Flink;
    }

    return pNextIrp;
}

__drv_raisesIRQL(DISPATCH_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
VOID DkCsqAcquireLock(__in PIO_CSQ pCsq, __out __drv_out_deref(__drv_savesIRQL) PKIRQL pKIrql)
{
    PDEVICE_EXTENSION  pDevExt = NULL;

    pDevExt = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                context.control.ioCsq);

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    KeAcquireSpinLock(&pDevExt->context.control.csqSpinLock, pKIrql);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
VOID DkCsqReleaseLock(__in PIO_CSQ pCsq, __in __drv_in(__drv_restoresIRQL) KIRQL kIrql)
{
    PDEVICE_EXTENSION  pDevExt = NULL;

    pDevExt = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                context.control.ioCsq);

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    KeReleaseSpinLock(&pDevExt->context.control.csqSpinLock, kIrql);
}

VOID DkCsqCompleteCanceledIrp(__in PIO_CSQ pCsq, __in PIRP pIrp)
{
    DkCsqCompleteRead(pCsq, pIrp, STATUS_CANCELLED, 0);
}

/* Exactly one CSQ owner calls this, with neither driver spinlock held.
 * The extra read acquisition remains held through IoCompleteRequest. */
VOID DkCsqCompleteRead(PIO_CSQ pCsq, PIRP pIrp, NTSTATUS status, ULONG_PTR bytes)
{
    PDEVICE_EXTENSION ext = CONTAINING_RECORD(pCsq, DEVICE_EXTENSION,
                                              context.control.ioCsq);
    PVOID tag = pIrp;
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = bytes;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    IoReleaseRemoveLock(&ext->removeLock, tag);
}

VOID DkCsqDrainQueue(PIO_CSQ pCsq, PFILE_OBJECT fileObject)
{
    PIRP irp;
    while ((irp = IoCsqRemoveNextIrp(pCsq, fileObject)) != NULL)
    {
        DkCsqCompleteCanceledIrp(pCsq, irp);
    }
}

VOID DkCsqCleanUpQueue(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    PIO_STACK_LOCATION  pStack = NULL;
    PDEVICE_EXTENSION   pDevExt = NULL;


    pDevExt = (PDEVICE_EXTENSION) pDevObj->DeviceExtension;

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    pStack = IoGetCurrentIrpStackLocation(pIrp);

    DkCsqDrainQueue(&pDevExt->context.control.ioCsq, pStack->FileObject);
}

