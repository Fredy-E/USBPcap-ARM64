/*
 * Copyright (c) 2013-2019 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "USBPcapMain.h"
#include <Wdmsec.h>
#include "USBPcapRootHubControl.h"
#include "Ntstrsafe.h"

extern LONG volatile g_controlId;

#define NTNAME_PREFIX      L"\\Device\\USBPcap"
#define SYMBOLIC_PREFIX    L"\\DosDevices\\USBPcap"
#define MAX_CONTROL_ID     L"65535"

#define MAX_NTNAME_LEN     (sizeof(NTNAME_PREFIX)+sizeof(MAX_CONTROL_ID))
#define MAX_SYMBOLIC_LEN   (sizeof(SYMBOLIC_PREFIX)+sizeof(MAX_CONTROL_ID))

DECLARE_CONST_UNICODE_STRING(
    SDDL_DEVOBJ_SYS_ALL_ADM_ALL_EVERYONE_ANY,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GX;;;WD)(A;;GX;;;RC)"
);

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS USBPcapCreateRootHubControlDevice(IN PDEVICE_EXTENSION hubExt,
                                           OUT PDEVICE_OBJECT *control,
                                           OUT USHORT *busId)
{
    UNICODE_STRING     ntDeviceName;
    UNICODE_STRING     symbolicLinkName;
    PDEVICE_OBJECT     controlDevice = NULL;
    PDEVICE_EXTENSION  controlExt = NULL;
    NTSTATUS           status;
    USHORT             id;
    LONG               nextId;
    WCHAR              ntNameBuffer[MAX_NTNAME_LEN / sizeof(WCHAR)];
    WCHAR              symbolicNameBuffer[MAX_SYMBOLIC_LEN / sizeof(WCHAR)];
    PUSBPCAP_ROOTHUB_DATA rootData = hubExt->context.usb.pDeviceData->pRootData;
    KIRQL irql;
    BOOLEAN published = FALSE;

    *control = NULL;
    *busId = 0;

    ASSERT(hubExt->deviceMagic == USBPCAP_MAGIC_ROOTHUB);

    /* Acquire the control device ID */
    nextId = InterlockedIncrement(&g_controlId);
    if (nextId <= 0 || nextId > MAXUSHORT)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    id = (USHORT)nextId;

    ntDeviceName.Length = 0;
    ntDeviceName.MaximumLength = MAX_NTNAME_LEN;
    ntDeviceName.Buffer = (PWSTR)ntNameBuffer;

    symbolicLinkName.Length = 0;
    symbolicLinkName.MaximumLength = MAX_SYMBOLIC_LEN;
    symbolicLinkName.Buffer = (PWSTR)symbolicNameBuffer;

    status = RtlUnicodeStringPrintf(&ntDeviceName,
                                    NTNAME_PREFIX L"%hu", id);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = RtlUnicodeStringPrintf(&symbolicLinkName,
                                    SYMBOLIC_PREFIX L"%hu", id);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    KdPrint(("Creating device %wZ (%wZ)\n",
            &ntDeviceName, &symbolicLinkName));

    status = IoCreateDeviceSecure(hubExt->pDrvObj,
                                  sizeof(DEVICE_EXTENSION),
                                  &ntDeviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE, /* Non-Exclusive device */
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL_EVERYONE_ANY,
                                  NULL,
                                  &controlDevice);

    if (NT_SUCCESS(status))
    {
        controlDevice->Flags |= DO_DIRECT_IO;


        controlExt = (PDEVICE_EXTENSION)controlDevice->DeviceExtension;
        controlExt->deviceMagic      = USBPCAP_MAGIC_CONTROL;
        controlExt->pThisDevObj      = controlDevice;
        controlExt->pNextDevObj      = NULL;
        controlExt->pDrvObj          = hubExt->pDrvObj;

        IoInitializeRemoveLock(&controlExt->removeLock, 0, 0, 0);
        controlExt->parentRemoveLock = NULL;
        status = IoAcquireRemoveLock(&hubExt->removeLock, NULL);
        if (!NT_SUCCESS(status))
        {
            goto End;
        }
        controlExt->parentRemoveLock = &hubExt->removeLock;

        /* Initialize USBPcap control context */
        controlExt->context.control.id             = id;
        controlExt->context.control.pRootHubObject = hubExt->pThisDevObj;
        controlExt->context.control.pCaptureObject = NULL;


        KeInitializeSpinLock(&controlExt->context.control.csqSpinLock);
        KeInitializeMutex(&controlExt->context.control.captureMutex, 0);
        controlExt->context.control.removing = FALSE;
        controlExt->context.control.captureClosing = FALSE;
        InitializeListHead(&controlExt->context.control.lePendIrp);
        status = IoCsqInitializeEx(&controlExt->context.control.ioCsq,
                                 DkCsqInsertIrp, DkCsqRemoveIrp,
                                 DkCsqPeekNextIrp, DkCsqAcquireLock,
                                 DkCsqReleaseLock, DkCsqCompleteCanceledIrp);
        if (!NT_SUCCESS(status))
        {
            DkDbgVal("Error initialize Cancel-safe queue!", status);
            goto End;
        }

        /* Root fields and parent reference precede any publication. */
        KeAcquireSpinLock(&rootData->bufferLock, &irql);
        rootData->controlDevice = controlDevice;
        rootData->busId = id;
        published = TRUE;
        KeReleaseSpinLock(&rootData->bufferLock, irql);
        status = IoCreateSymbolicLink(&symbolicLinkName, &ntDeviceName);
        if (!NT_SUCCESS(status))
        {
            KeAcquireSpinLock(&rootData->bufferLock, &irql);
            rootData->controlDevice = NULL;
            KeReleaseSpinLock(&rootData->bufferLock, irql);
            goto End;
        }
        controlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    }
    else
    {
        KdPrint(("IoCreateDevice failed %x\n", status));
    }

End:
    if ((!NT_SUCCESS(status)) || (controlExt == NULL))
    {
        if (controlDevice != NULL)
        {
            if (published)
            {
                /* A producer could have observed publication even while
                 * DO_DEVICE_INITIALIZING still prevents user opens. Revoke
                 * and wait for those transient owners before failure delete. */
                KeAcquireSpinLock(&controlExt->context.control.csqSpinLock, &irql);
                controlExt->context.control.removing = TRUE;
                controlExt->context.control.captureClosing = TRUE;
                KeReleaseSpinLock(&controlExt->context.control.csqSpinLock, irql);
                DkCsqDrainQueue(&controlExt->context.control.ioCsq, NULL);
                if (NT_SUCCESS(IoAcquireRemoveLock(&controlExt->removeLock, NULL)))
                {
                    IoReleaseRemoveLockAndWait(&controlExt->removeLock, NULL);
                }
            }
            if (controlExt != NULL && controlExt->parentRemoveLock != NULL)
            {
                IoReleaseRemoveLock(controlExt->parentRemoveLock, NULL);
                controlExt->parentRemoveLock = NULL;
            }
            IoDeleteDevice(controlDevice);
        }
    }
    else
    {
        *control = controlDevice;
        *busId = id;
    }

    return status;
}


VOID USBPcapDeleteRootHubControlDevice(IN PDEVICE_OBJECT controlDevice)
{
    UNICODE_STRING     symbolicLinkName;
    WCHAR              symbolicNameBuffer[MAX_SYMBOLIC_LEN / sizeof(WCHAR)];
    USHORT             id;
    PDEVICE_EXTENSION  pDevExt;
    NTSTATUS           status;
    PDEVICE_EXTENSION rootExt;
    PUSBPCAP_ROOTHUB_DATA rootData;
    PIO_REMOVE_LOCK parentLock;
    KIRQL irql;

    pDevExt = ((PDEVICE_EXTENSION)controlDevice->DeviceExtension);

    ASSERT(pDevExt->deviceMagic == USBPCAP_MAGIC_CONTROL);

    id = pDevExt->context.control.id;

    symbolicLinkName.Length = 0;
    symbolicLinkName.MaximumLength = MAX_SYMBOLIC_LEN;
    symbolicLinkName.Buffer = (PWSTR)symbolicNameBuffer;

    status = RtlUnicodeStringPrintf(&symbolicLinkName,
                                    SYMBOLIC_PREFIX L"%hu", id);

    if (!NT_SUCCESS(IoAcquireRemoveLock(&pDevExt->removeLock, NULL)))
    {
        return;
    }
    /* Serialize with passive state changes, close CSQ admission and revoke
     * producer publication before drain/wait. No completion under locks. */
    KeWaitForSingleObject(&pDevExt->context.control.captureMutex,
                          Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&pDevExt->context.control.csqSpinLock, &irql);
    pDevExt->context.control.removing = TRUE;
    pDevExt->context.control.captureClosing = TRUE;
    KeReleaseSpinLock(&pDevExt->context.control.csqSpinLock, irql);
    rootExt = (PDEVICE_EXTENSION)pDevExt->context.control.pRootHubObject->DeviceExtension;
    rootData = rootExt->context.usb.pDeviceData->pRootData;
    KeAcquireSpinLock(&rootData->bufferLock, &irql);
    rootData->controlDevice = NULL;
    RtlZeroMemory(&rootData->filter, sizeof(rootData->filter));
    KeReleaseSpinLock(&rootData->bufferLock, irql);
    KeReleaseMutex(&pDevExt->context.control.captureMutex, FALSE);
    if (NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symbolicLinkName);
    }
    DkCsqDrainQueue(&pDevExt->context.control.ioCsq, NULL);
    IoReleaseRemoveLockAndWait(&pDevExt->removeLock, NULL);
    parentLock = pDevExt->parentRemoveLock;
    pDevExt->parentRemoveLock = NULL;
    pDevExt->context.control.pRootHubObject = NULL;
    IoDeleteDevice(controlDevice);
    IoReleaseRemoveLock(parentLock, NULL);
}

