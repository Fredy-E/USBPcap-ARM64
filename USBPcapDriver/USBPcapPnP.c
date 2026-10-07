/*
 * Copyright (c) 2013-2019 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "USBPcapMain.h"
#include "USBPcapHelperFunctions.h"
#include "USBPcapRootHubControl.h"

NTSTATUS DkPnP(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS             ntStat = STATUS_SUCCESS;
    PDEVICE_EXTENSION    pDevExt = NULL;
    PIO_STACK_LOCATION   pStack = NULL;

    pDevExt = (PDEVICE_EXTENSION) pDevObj->DeviceExtension;

    pStack = IoGetCurrentIrpStackLocation(pIrp);

    if (pDevExt->deviceMagic == USBPCAP_MAGIC_ROOTHUB)
    {
        return DkHubFltPnP(pDevExt, pStack, pIrp);
    }
    else if (pDevExt->deviceMagic == USBPCAP_MAGIC_DEVICE)
    {
        return DkTgtPnP(pDevExt, pStack, pIrp);
    }
    else
    {
        // Do nothing
    }

    ntStat = IoAcquireRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
    if (!NT_SUCCESS(ntStat))
    {
        DkDbgVal("Error acquire lock!", ntStat);
        DkCompleteRequest(pIrp, ntStat, 0);
        return ntStat;
    }

    if (pDevExt->pNextDevObj == NULL)
    {
        ntStat = STATUS_INVALID_DEVICE_REQUEST;
        DkCompleteRequest(pIrp, ntStat, 0);
    }
    else
    {
        IoSkipCurrentIrpStackLocation(pIrp);
        ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

    return ntStat;
}


NTSTATUS DkHubFltPnP(PDEVICE_EXTENSION pDevExt, PIO_STACK_LOCATION pStack, PIRP pIrp)
{
    NTSTATUS  ntStat = STATUS_SUCCESS;

    ntStat = IoAcquireRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
    if (!NT_SUCCESS(ntStat))
    {
        DkDbgVal("Error lock!", ntStat);
        DkCompleteRequest(pIrp, ntStat, 0);
        return ntStat;
    }

    switch (pStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
            DkDbgStr("IRP_MN_START_DEVICE");

            ntStat = DkForwardAndWait(pDevExt->pNextDevObj, pIrp);
            IoCompleteRequest(pIrp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

            return ntStat;

        case IRP_MN_SURPRISE_REMOVAL:
        {
            PUSBPCAP_ROOTHUB_DATA rootData = pDevExt->context.usb.pDeviceData->pRootData;
            if (rootData->controlDevice != NULL)
            {
                USBPcapDeleteRootHubControlDevice(rootData->controlDevice);
            }
            break; /* Preserve ordinary lower-stack PnP forwarding. */
        }

        case IRP_MN_REMOVE_DEVICE:
        {
            PUSBPCAP_DEVICE_DATA pDeviceData = pDevExt->context.usb.pDeviceData;
            DkDbgStr("IRP_MN_REMOVE_DEVICE");

            IoSkipCurrentIrpStackLocation(pIrp);
            ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);

            if (pDeviceData != NULL &&
                pDeviceData->pRootData != NULL &&
                pDeviceData->pRootData->controlDevice != NULL)
            {
                USBPcapDeleteRootHubControlDevice(pDeviceData->pRootData->controlDevice);
            }

            IoReleaseRemoveLockAndWait(&pDevExt->removeLock, (PVOID) pIrp);

            DkDetachAndDeleteHubFilt(pDevExt);

            return ntStat;
        }

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            DkDbgStr("IRP_MN_QUERY_DEVICE_RELATIONS");
            ntStat = DkHubFltPnpHandleQryDevRels(pDevExt, pStack, pIrp);

            IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
            return ntStat;

        default:
            DkDbgVal("", pStack->MinorFunction);
            break;

    }

    if (pDevExt->pNextDevObj == NULL)
    {
        ntStat = STATUS_INVALID_DEVICE_REQUEST;
        DkCompleteRequest(pIrp, ntStat, 0);
    }
    else
    {
        IoSkipCurrentIrpStackLocation(pIrp);
        ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

    return ntStat;
}

NTSTATUS DkTgtPnP(PDEVICE_EXTENSION pDevExt, PIO_STACK_LOCATION pStack, PIRP pIrp)
{
    NTSTATUS             ntStat = STATUS_SUCCESS;
    PUSBPCAP_DEVICE_DATA  pDeviceData = pDevExt->context.usb.pDeviceData;

    ntStat = IoAcquireRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
    if (!NT_SUCCESS(ntStat))
    {
        DkDbgVal("Error lock!", ntStat);
        DkCompleteRequest(pIrp, ntStat, 0);
        return ntStat;
    }

    switch (pStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            DEVICE_EXTENSION queryExtension = {0};
            USBPCAP_DEVICE_DATA queryData = {0};
            KIRQL metadataIrql;
            PVOID endpoint;

            /* START is a publication boundary, including on restart. Withdraw
             * the previous address before any lower/query completion reentry.
             * Unknown metadata must not be stored in the endpoint table. */
            KeAcquireSpinLock(&pDeviceData->tablesSpinLock, &metadataIrql);
            pDeviceData->properData = FALSE;
            pDeviceData->parentPort = 0;
            pDeviceData->deviceAddress = 255; /* UNKNOWN / capture unavailable */
            pDeviceData->isHub = FALSE;
            if (pDeviceData->endpointTable != NULL)
            {
                while ((endpoint = RtlGetElementGenericTable(
                            pDeviceData->endpointTable, 0)) != NULL)
                {
                    RtlDeleteElementGenericTable(pDeviceData->endpointTable,
                                                  endpoint);
                }
            }
            KeReleaseSpinLock(&pDeviceData->tablesSpinLock, metadataIrql);

            /* Query pageable helpers only after successful lower START, and
             * only into private staging data: the helper can fail after a
             * partial port update. Its filter update uses root bufferLock. */
            ntStat = DkForwardAndWait(pDevExt->pNextDevObj, pIrp);
            if (NT_SUCCESS(ntStat))
            {
                queryExtension.deviceMagic = pDevExt->deviceMagic;
                queryExtension.pNextDevObj = pDevExt->pNextDevObj;
                queryExtension.context.usb.pDeviceData = &queryData;
                queryData.pNextParentFlt = pDeviceData->pNextParentFlt;
                queryData.pRootData = pDeviceData->pRootData;
                if (NT_SUCCESS(USBPcapGetDeviceUSBInfo(&queryExtension)))
                {
                    KeAcquireSpinLock(&pDeviceData->tablesSpinLock,
                                      &metadataIrql);
                    pDeviceData->parentPort = queryData.parentPort;
                    pDeviceData->isHub = queryData.isHub;
                    pDeviceData->deviceAddress = queryData.deviceAddress;
                    pDeviceData->properData = TRUE;
                    KeReleaseSpinLock(&pDeviceData->tablesSpinLock,
                                      metadataIrql);
                }
                /* Information failure omits capture metadata, never changes
                 * the successful lower START status or IRP information. */
            }
            IoCompleteRequest(pIrp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
            return ntStat;
        }

        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            BOOLEAN isHub;
            KIRQL metadataIrql;
            /* Metadata publication and topology decisions share one lock. */
            KeAcquireSpinLock(&pDeviceData->tablesSpinLock, &metadataIrql);
            isHub = pDeviceData->properData && pDeviceData->isHub;
            KeReleaseSpinLock(&pDeviceData->tablesSpinLock, metadataIrql);
            /* Do not create child filters for composite/unknown devices. */
            if (isHub)
            {
                DkDbgStr("IRP_MN_QUERY_DEVICE_RELATIONS");
                ntStat = DkHubFltPnpHandleQryDevRels(pDevExt, pStack, pIrp);

                IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
                return ntStat;
            }
            else
            {
                break;
            }
        }

        case IRP_MN_REMOVE_DEVICE:
            DkDbgStr("IRP_MN_REMOVE_DEVICE");

            IoSkipCurrentIrpStackLocation(pIrp);
            ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);

            IoReleaseRemoveLockAndWait(&pDevExt->removeLock, (PVOID) pIrp);

            DkDetachAndDeleteTgt(pDevExt);

            return ntStat;


        default:
            DkDbgVal("", pStack->MinorFunction);
            break;

    }

    if (pDevExt->pNextDevObj == NULL)
    {
        ntStat = STATUS_INVALID_DEVICE_REQUEST;
        DkCompleteRequest(pIrp, ntStat, 0);
    }
    else
    {
        IoSkipCurrentIrpStackLocation(pIrp);
        ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

    return ntStat;
}

NTSTATUS DkHubFltPnpHandleQryDevRels(PDEVICE_EXTENSION pDevExt, PIO_STACK_LOCATION pStack, PIRP pIrp)
{
    NTSTATUS             ntStat = STATUS_SUCCESS;
    PDEVICE_RELATIONS    pDevRel = NULL;
    PUSBPCAP_DEVICE_DATA pDeviceData = pDevExt->context.usb.pDeviceData;
    ULONG                i;

    ntStat = IoAcquireRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);
    if (!NT_SUCCESS(ntStat))
    {
        DkDbgVal("Error lock!", ntStat);
        DkCompleteRequest(pIrp, ntStat, 0);
        return ntStat;
    }

    /* PnP manager sends this at PASSIVE_LEVEL */
    switch (pStack->Parameters.QueryDeviceRelations.Type)
    {
        case BusRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: BusRelations");

            ntStat = DkForwardAndWait(pDevExt->pNextDevObj, pIrp);

            // After we forward the request, the bus driver have created or deleted
            // a child device object. When bus driver created one (or more), this is the PDO
            // of our target device, we create and attach a filter object to it.
            // Note that we only attach the last detected USB device on it's Hub.
            if (NT_SUCCESS(ntStat))
            {
                pDevRel = (PDEVICE_RELATIONS) pIrp->IoStatus.Information;
                if (pDevRel)
                {
                    PDEVICE_OBJECT *children = NULL;
                    ULONG tracked = 0;
                    /* Allocate bookkeeping before attaching anything. On
                     * failure retain the previous list: forgetting attached
                     * children would stack duplicate filters next query. */
                    if ((SIZE_T)pDevRel->Count <
                        ((SIZE_T)-1) / sizeof(PDEVICE_OBJECT))
                    {
                        children = ExAllocatePoolWithTag(NonPagedPool,
                            ((SIZE_T)pDevRel->Count + 1) * sizeof(PDEVICE_OBJECT),
                            DKPORT_MTAG);
                    }
                    if (children == NULL)
                    {
                        DkDbgStr("Cannot track children; retaining existing filters");
                        goto CompleteBusRelations;
                    }
                    USBPcapPrintUSBPChildrenInformation(pDevExt->pNextDevObj);

                    DkDbgVal("Child(s) number", pDevRel->Count);

                    for (i = 0; i < pDevRel->Count; i++)
                    {
                        PDEVICE_OBJECT *child;
                        BOOLEAN        found = FALSE;

                        child = pDeviceData->previousChildren;

                        /* Search only if there are any children */
                        if (child != NULL)
                        {
                            while (*child != NULL)
                            {
                                if (*child == pDevRel->Objects[i])
                                {
                                    found = TRUE;
                                    break;
                                }
                                child++;
                            }
                        }

                        if (found == FALSE)
                        {
                            /* New device attached */
                            found = NT_SUCCESS(DkCreateAndAttachTgt(pDevExt,
                                                 pDevRel->Objects[i]));
                        }
                        if (found)
                        {
                            children[tracked++] = pDevRel->Objects[i];
                        }
                    }

                    /* Free old children information */
                    if (pDeviceData->previousChildren != NULL)
                    {
                        ExFreePool(pDeviceData->previousChildren);
                        pDeviceData->previousChildren = NULL;
                    }

                    children[tracked] = NULL;
                    pDeviceData->previousChildren = children;
                }
            }

CompleteBusRelations:
            IoCompleteRequest(pIrp, IO_NO_INCREMENT);

            IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

            return ntStat;


        case EjectionRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: EjectionRelations");
            break;
        case RemovalRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: RemovalRelations");
            break;
        case TargetDeviceRelation:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: TargetDeviceRelation");
            break;
        case PowerRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: PowerRelations");
            break;
        case SingleBusRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: SingleBusRelations");
            break;
        case TransportRelations:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: TransportRelations");
            break;

        default:
            DkDbgStr("PnP, IRP_MN_QUERY_DEVICE_RELATIONS: Unknown query relation type");
            break;
    }

    if (pDevExt->pNextDevObj == NULL)
    {
        ntStat = STATUS_INVALID_DEVICE_REQUEST;
        DkCompleteRequest(pIrp, ntStat, 0);
    }
    else
    {
        IoSkipCurrentIrpStackLocation(pIrp);
        ntStat = IoCallDriver(pDevExt->pNextDevObj, pIrp);
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, (PVOID) pIrp);

    return ntStat;
}
