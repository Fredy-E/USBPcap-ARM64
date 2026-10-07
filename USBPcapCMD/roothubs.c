/*
 * Copyright (c) 2013 Tomasz Moń <desowin@gmail.com>
 *
 * Based on devcon sample
 *   Copyright (c) Microsoft Corporation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <windows.h>
#include <Setupapi.h>
#include <Usbiodef.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

typedef struct {
    LPTSTR *array;
    int used;
    int size;
    BOOL failed;
} StringArray;

static StringArray non_standard_hwids; /* Stores non standard HWIDs. */

static void init_string_array(StringArray *a, int initial_size)
{
    a->array = NULL;
    a->used = a->size = 0;
    a->failed = FALSE;
    if (initial_size <= 0 || (size_t)initial_size > (size_t)-1 / sizeof(LPTSTR))
    {
        a->failed = TRUE;
        return;
    }
    a->array = (LPTSTR *)malloc((size_t)initial_size * sizeof(LPTSTR));
    if (a->array == NULL) { a->failed = TRUE; return; }
    a->size = initial_size;
}

static BOOL insert_string_array(StringArray *a, LPTSTR hwid)
{
    LPTSTR copy;
    if (a->failed || hwid == NULL) { a->failed = TRUE; return FALSE; }
    copy = _tcsdup(hwid);
    if (copy == NULL) { a->failed = TRUE; return FALSE; }
    if (a->used == a->size)
    {
        LPTSTR *tmp;
        int capacity;
        if (a->size <= 0 || a->size > INT_MAX / 2 ||
            (size_t)a->size * 2 > (size_t)-1 / sizeof(LPTSTR))
        {
            free(copy);
            a->failed = TRUE;
            return FALSE;
        }
        capacity = a->size * 2;
        tmp = (LPTSTR *)realloc(a->array, (size_t)capacity * sizeof(LPTSTR));
        if (tmp == NULL)
        {
            free(copy);
            a->failed = TRUE;
            return FALSE;
        }
        a->array = tmp;
        a->size = capacity; /* Publish only after successful growth. */
    }
    a->array[a->used++] = copy;
    return TRUE;
}

static void free_string_array(StringArray *a)
{
    int i;
    for (i = 0; i < a->used; i++)
    {
        free(a->array[i]);
    }
    free(a->array);
    a->array = NULL;
    a->used = a->size = 0;
}

static BOOL is_standard_hwid(LPTSTR hwid)
{
    if (hwid == NULL)
    {
        return FALSE;
    }
    else if (_tcscmp("USB\\ROOT_HUB", hwid) == 0)
    {
        return TRUE;
    }
    else if (_tcscmp("USB\\ROOT_HUB20", hwid) == 0)
    {
        return TRUE;
    }
    else if (_tcscmp("USB\\ROOT_HUB30", hwid) == 0)
    {
        return TRUE;
    }

    return FALSE;
}

static BOOL add_non_standard_hwid(LPTSTR hwid)
{
    return insert_string_array(&non_standard_hwids, hwid);
}

static BOOL is_non_standard_hwid_known(LPTSTR hwid)
{
    int i;
    for (i = 0; i < non_standard_hwids.used; i++)
    {
        if (_tcscmp(non_standard_hwids.array[i], hwid) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static PTSTR build_non_standard_reg_multi_sz(StringArray *a, int *length)
{
    PTSTR multi_sz;
    size_t chars = 1;
    size_t offset = 0;
    int i;
    *length = 0;
    if (a->failed) return NULL;
    for (i = 0; i < a->used; i++)
    {
        size_t count;
        if (a->array[i] == NULL) return NULL;
        count = _tcslen(a->array[i]);
        if (count >= INT_MAX / sizeof(TCHAR)) return NULL;
        ++count;
        if (chars > INT_MAX / sizeof(TCHAR) - count) return NULL;
        chars += count;
    }
    if (chars == 1) chars = 2; /* Empty MULTI_SZ still needs two NULs. */
    multi_sz = (PTSTR)malloc(chars * sizeof(TCHAR));
    if (multi_sz == NULL) return NULL;
    memset(multi_sz, 0, chars * sizeof(TCHAR));
    for (i = 0; i < a->used; i++)
    {
        size_t count = _tcslen(a->array[i]) + 1;
        memcpy(multi_sz + offset, a->array[i], count * sizeof(TCHAR));
        offset += count;
    }
    *length = (int)(chars * sizeof(TCHAR));
    return multi_sz;
}

static void set_non_standard_hwids_reg_key(PTSTR multi_sz, int length)
{
    HKEY hkey;
    LONG regVal;

    regVal = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                           _T("SYSTEM\\CurrentControlSet\\services\\USBPcap"),
                           0,
                           KEY_SET_VALUE,
                           &hkey);

    if (regVal == ERROR_SUCCESS)
    {
        regVal = RegSetValueEx(hkey,
                       _T("NonStandardHWIDs"),
                       0,
                       REG_MULTI_SZ,
                       (const BYTE*)multi_sz,
                       length);

        if (regVal != ERROR_SUCCESS)
        {
            fprintf(stderr, "Failed to set NonStandardHWIDs value\n");
        }

        RegCloseKey(hkey);
    }
    else
    {
        fprintf(stderr, "Failed to open USBPcap service key\n");
    }
}

/*
 * Returns index array for given MultiSz.
 *
 * Returns NULL-terminated array of strings on success.
 * Array must be freed using DelMultiSz().
 * Returns NULL on failure.
 */
__drv_allocatesMem(object)
static LPTSTR * GetMultiSzIndexArray(__in __drv_aliasesMem LPTSTR MultiSz)
{
    LPTSTR scan;
    LPTSTR *array;
    size_t elements;

    for (scan = MultiSz, elements = 0; scan[0] ;elements++)
    {
        scan += lstrlen(scan)+1;
    }
    if (elements > (size_t)-1 / sizeof(LPTSTR) - 2) return NULL;
    array = (LPTSTR*)malloc(sizeof(LPTSTR) * (elements+2));
    if(!array)
    {
        return NULL;
    }
    array[0] = MultiSz;
    array++;
    if (elements)
    {
        for (scan = MultiSz, elements = 0; scan[0]; elements++)
        {
            array[elements] = scan;
            scan += lstrlen(scan) + 1;
        }
    }
    array[elements] = NULL;
    return array;
}

/*
 * Retrieves multi-sz devnode registry property for given DEVINST.
 * NULL with ERROR_NOT_ENOUGH_MEMORY means preparation failed, not absence.
 * Missing/invalid/unavailable properties return NULL with ERROR_SUCCESS.
 *
 * Returns NULL-terminated array of strings on success.
 * Array must be freed using DelMultiSz().
 * Returns NULL on failure.
 */
__drv_allocatesMem(object)
static LPTSTR *GetDevMultiSz(DEVINST roothub, ULONG property)
{
    LPTSTR buffer;
    ULONG size;
    ULONG capacity;
    ULONG dataType;
    LPTSTR * array;
    DWORD szChars;
    CONFIGRET ret;
    DWORD error = ERROR_SUCCESS;

    size = 0;
    buffer = NULL;
    SetLastError(ERROR_SUCCESS);

    ret = CM_Get_DevNode_Registry_Property(roothub, property, &dataType,
                                           buffer, &size, 0);

    if (ret != CR_BUFFER_SMALL || dataType != REG_MULTI_SZ)
    {
        goto failed;
    }

    if (size == 0)
    {
        goto failed;
    }
    capacity = size;
    if ((size_t)capacity / sizeof(TCHAR) > (size_t)-1 / sizeof(TCHAR) - 2)
    {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }
    buffer = malloc(((size_t)capacity / sizeof(TCHAR) + 2) * sizeof(TCHAR));
    if (!buffer)
    {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto failed;
    }

    ret = CM_Get_DevNode_Registry_Property(roothub, property, &dataType,
                                           buffer, &size, 0);

    if (ret == CR_SUCCESS && dataType == REG_MULTI_SZ && size <= capacity && size % sizeof(TCHAR) == 0)
    {
        szChars = size/sizeof(TCHAR);
        buffer[szChars] = TEXT('\0');
        buffer[szChars+1] = TEXT('\0');
        array = GetMultiSzIndexArray(buffer);
        if (array)
        {
            SetLastError(ERROR_SUCCESS);
            return array;
        }
        error = ERROR_NOT_ENOUGH_MEMORY;
    }

failed:
    if (buffer)
    {
        free(buffer);
    }
    SetLastError(error);
    return NULL;
}

/*
 * Frees array allocated by GetDevMultiSz()
 */
static void DelMultiSz(__in_opt __drv_freesMem(object) LPTSTR* Array)
{
    if(Array)
    {
        Array--;
        if(Array[0])
        {
            free(Array[0]);
        }
        free(Array);
    }
}


void find_non_standard_hwids(HDEVINFO devs,
                             PSP_DEVINFO_DATA devInfo,
                             PSP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail)
{
    LPTSTR *hwIds = NULL;
    LPTSTR *compatIds = NULL;
    LPTSTR *tmpIds = NULL;
    CONFIGRET cr;
    DEVINST roothub;

    /* Assume that all host controller children are Root Hubs */
    cr = CM_Get_Child(&roothub, devInfo->DevInst, 0);

    while (cr == CR_SUCCESS && !non_standard_hwids.failed)
    {
        BOOL standard = FALSE;

        hwIds = GetDevMultiSz(roothub, CM_DRP_HARDWAREID);
        if (hwIds == NULL && GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
            non_standard_hwids.failed = TRUE;
        compatIds = GetDevMultiSz(roothub, CM_DRP_COMPATIBLEIDS);
        if (compatIds == NULL && GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
            non_standard_hwids.failed = TRUE;
        if (non_standard_hwids.failed)
        {
            DelMultiSz(hwIds);
            DelMultiSz(compatIds);
            break;
        }

        if (hwIds && hwIds[0] != NULL)
        {
            for (tmpIds = hwIds; tmpIds[0] != NULL; tmpIds++)
            {
                printf("Hardware ID: %s\n", tmpIds[0]);
                if (is_standard_hwid(tmpIds[0]) == TRUE)
                {
                    printf("Found standard HWID\n");
                    standard = TRUE;
                }
            }

            if (standard == FALSE)
            {
                printf("RootHub does not have standard HWID! ");

                if (is_non_standard_hwid_known(hwIds[0]) == TRUE)
                {
                    printf("%s is already in the non-standard list.\n", hwIds[0]);
                }
                else
                {
                    if (add_non_standard_hwid(hwIds[0]))
                        printf("Added %s to non-standard list.\n", hwIds[0]);
                }
            }
        }

        if (compatIds)
        {
            for (tmpIds = compatIds; tmpIds[0] != NULL; tmpIds++)
            {
                printf("Compatible ID: %s\n", tmpIds[0]);
            }
        }

        DelMultiSz(hwIds);
        DelMultiSz(compatIds);

        cr = CM_Get_Sibling(&roothub, roothub, 0);
    }
}

void restart_device(HDEVINFO devs,
                    PSP_DEVINFO_DATA devInfo,
                    PSP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail)
{
    SP_PROPCHANGE_PARAMS pcp;
    SP_DEVINSTALL_PARAMS devParams;
    TCHAR devID[MAX_DEVICE_ID_LEN];

    if (CM_Get_Device_ID_Ex(devInfo->DevInst, devID, MAX_DEVICE_ID_LEN, 0, devInfoListDetail->RemoteMachineHandle) != CR_SUCCESS)
    {
        devID[0] = TEXT('\0');
        printf("Unknown instance ID: ");
    }
    else
    {
        printf("%s: ", devID);
    }

    pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    pcp.StateChange = DICS_PROPCHANGE;
    pcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
    pcp.HwProfile = 0;

    if (!SetupDiSetClassInstallParams(devs, devInfo, &pcp.ClassInstallHeader, sizeof(pcp)) ||
        !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, devs, devInfo))
    {
        fprintf(stderr, "Failed to invoke DIF_PROPERTYCHANGE! Please reboot.\n");
    }
    else
    {
        devParams.cbSize = sizeof(devParams);

        if (SetupDiGetDeviceInstallParams(devs,devInfo,&devParams) &&
            (devParams.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT)))
        {
            printf("Reboot required.\n");
        }
        else
        {
            printf("Restarted.\n");
        }
    }
}

static void foreach_host_controller(
    void (*callback)(HDEVINFO devs,
                     PSP_DEVINFO_DATA devInfo,
                     PSP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail))
{
    HDEVINFO devs = INVALID_HANDLE_VALUE;
    DWORD devIndex;
    SP_DEVINFO_DATA devInfo;
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;

    devs = SetupDiGetClassDevsEx(&GUID_DEVINTERFACE_USB_HOST_CONTROLLER,
            NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
            NULL, NULL, NULL);

    if(devs == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "SetupDiCreateDeviceInfoListEx() failed\n");
        goto final;
    }

    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if (!SetupDiGetDeviceInfoListDetail(devs, &devInfoListDetail))
    {
        fprintf(stderr, "SetupDiGetDeviceInfoListDetail() failed\n");
        goto final;
    }

    devInfo.cbSize = sizeof(devInfo);
    for (devIndex = 0; SetupDiEnumDeviceInfo(devs, devIndex, &devInfo); devIndex++)
    {
        callback(devs, &devInfo, &devInfoListDetail);
    }

final:
    if (devs != INVALID_HANDLE_VALUE)
    {
        SetupDiDestroyDeviceInfoList(devs);
    }
}

void init_non_standard_roothub_hwid()
{
    int length;
    PTSTR multi_sz;

    init_string_array(&non_standard_hwids, 1);

    if (!non_standard_hwids.failed) foreach_host_controller(find_non_standard_hwids);

    if (!non_standard_hwids.failed && non_standard_hwids.used > 0)
    {
        multi_sz = build_non_standard_reg_multi_sz(&non_standard_hwids, &length);
        if (multi_sz != NULL) set_non_standard_hwids_reg_key(multi_sz, length);
        free(multi_sz);
    }

    free_string_array(&non_standard_hwids);
}

void restart_all_usb_devices()
{
    foreach_host_controller(restart_device);
}
