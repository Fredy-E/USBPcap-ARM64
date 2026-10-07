/*
 * Copyright (c) 2013-2018 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define _CRT_SECURE_NO_DEPRECATE

#include <initguid.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Shellapi.h>
#include <Shlwapi.h>
#include <Usbiodef.h>
#include "filters.h"
#include "thread.h"
#include "enum.h"
#include "getopt.h"
#include "roothubs.h"
#include "version.h"
#include "descriptors.h"
#include "USBPcap.h"

#define INPUT_BUFFER_SIZE 1024

#define DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE (1024*1024)
#define DEFAULT_SNAPSHOT_LENGTH             (65535)

static BOOL IsElevated()
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
        {
            fRet = Elevation.TokenIsElevated;
        }
        else
        {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER)
            {
                /* Running on Windows XP.
                 * Check if executed as administrator by reading Local Service key.
                 */
                HKEY key;
                if (ERROR_SUCCESS == RegOpenKey(HKEY_USERS, "S-1-5-19", &key))
                {
                    fRet = TRUE;
                    RegCloseKey(key);
                }
                else
                {
                    /* If we were executed with SW_HIDE then the runas window won't be shown.
                     * In such case pretend here that we are running as administrator so
                     * the process will fail (and not simply be waiting indefinitely
                     * without giving any clue).
                     */
                    STARTUPINFO info;
                    GetStartupInfo(&info);
                    if (info.wShowWindow == SW_HIDE)
                    {
                        fRet = TRUE;
                    }
                }
            }
            else
            {
                fprintf(stderr, "GetTokenInformation failed with code %d\n", err);
            }
        }
    }

    if (hToken)
    {
        CloseHandle(hToken);
    }

    return fRet;
}

/*
 * GetModuleFullName:
 *
 *    Gets the full path and file name of the specified module and returns the length on success,
 *    (which does not include the terminating NUL character) 0 otherwise.  Use GetLastError() to
 *    get extended error information.
 *
 *       hModule              [in] Handle to a module loaded by the calling process, or NULL to
 *                            use the current process module handle.  This function does not
 *                            retrieve the name for modules that were loaded using LoadLibraryEx
 *                            with the LOAD_LIBRARY_AS_DATAFILE flag. For more information, see
 *                            LoadLibraryEx.
 *
 *       pszBuffer            [out] Pointer to the buffer which receives the module full name.
 *                            This paramater may be NULL, in which case the function returns the
 *                            size of the buffer in characters required to contain the full name,
 *                            including a NUL terminating character.
 *
 *       nMaxChars            [in] Specifies the size of the buffer in characters.  This must be
 *                            0 when pszBuffer is NULL, otherwise the function fails.
 *
 *       ppszFileName         [out] On return, the referenced pointer is assigned a position in
 *                            the buffer to the module's file name only.  This parameter may be
 *                            NULL if the file name is not required.
 */
EXTERN_C int WINAPI GetModuleFullName(__in HMODULE hModule, __out LPWSTR pszBuffer,
                                      __in int nMaxChars, __out LPWSTR* ppszFileName)
{
    /* Determine required buffer size when requested */
    int nLength = 0;
    DWORD dwStatus = NO_ERROR;

    /* Validate parameters */
    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer == NULL && (nMaxChars != 0 || ppszFileName != NULL))
        {
             dwStatus = ERROR_INVALID_PARAMETER;
        }
        else if (pszBuffer != NULL && nMaxChars < 1)
        {
             dwStatus = ERROR_INVALID_PARAMETER;
        }
    }

    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer == NULL)
        {
            HANDLE hHeap = GetProcessHeap();

            WCHAR  cwBuffer[2048] = { 0 };
            LPWSTR pszBuffer      = cwBuffer;
            DWORD  dwMaxChars     = _countof(cwBuffer);
            DWORD  dwLength       = 0;

            LPWSTR pszNew;
            SIZE_T nSize;

            for (;;)
            {
                /* Try to get the module's full path and file name */
                dwLength = GetModuleFileNameW(hModule, pszBuffer, dwMaxChars);

                if (dwLength == 0)
                {
                    dwStatus = GetLastError();
                    break;
                }

                /* If succeeded, return buffer size requirement:
                 *    o  Adds one for the terminating NUL character.
                 */
                if (dwLength < dwMaxChars)
                {
                    nLength = (int)dwLength + 1;
                    break;
                }

                /* Check the maximum supported full name length:
                 *    o  Assumes support for HPFS, NTFS, or VTFS of ~32K.
                 */
                if (dwMaxChars >= 32768U)
                {
                    dwStatus = ERROR_BUFFER_OVERFLOW;
                    break;
                }

                /* Double the size of our buffer and try again */
                dwMaxChars *= 2;

                pszNew = (pszBuffer == cwBuffer ? NULL : pszBuffer);
                nSize  = (SIZE_T)dwMaxChars * sizeof(WCHAR);

                if (pszNew == NULL)
                {
                    pszNew = (LPWSTR)HeapAlloc(hHeap, 0, nSize);
                }
                else
                {
                    LPWSTR pszTmp;
                    pszTmp = (LPWSTR)HeapReAlloc(hHeap, 0, pszNew, nSize);
                    if (pszTmp == NULL)
                    {
                        HeapFree(hHeap, 0, pszNew);
                        if (pszNew == pszBuffer)
                        {
                            pszBuffer = NULL;
                        }
                        pszNew = NULL;
                    }
                    else
                    {
                        pszNew = pszTmp;
                    }
                }

                if (pszNew == NULL)
                {
                    dwStatus = ERROR_OUTOFMEMORY;
                    break;
                }

                pszBuffer = pszNew;
            }

            /* Free the temporary buffer if allocated */
            if (pszBuffer != cwBuffer)
            {
                if (!HeapFree(hHeap, 0, pszBuffer))
                {
                   dwStatus = GetLastError();
                }
            }
        }
    }

    /* Get the module's full name and pointer to file name when requested */
    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer != NULL)
        {
            nLength = (int)GetModuleFileNameW(hModule, pszBuffer, nMaxChars);

            if (nLength <= 0 || nLength == nMaxChars)
            {
                dwStatus = GetLastError();
            }
            else if (ppszFileName != NULL)
            {
                LPWSTR pszItr;
                *ppszFileName = pszBuffer;

                for (pszItr = pszBuffer; *pszItr != L'\0'; ++pszItr)
                {
                    if (*pszItr == L'\\' || *pszItr == L'/')
                    {
                        *ppszFileName = pszItr + 1;
                    }
               }
            }
         }
    }

    /* Return full name length or 0 on error */
    if (dwStatus != NO_ERROR)
    {
        nLength = 0;

        SetLastError(dwStatus);
    }

    return nLength;
}

/**
 *  Generates command line for worker process.
 *
 *  \param[in] data thread_data containing capture configuration.
 *  \param[out] appPath pointer to store application path. Must be freed using free().
 *  \param[out] appCmdLine commandline for worker process. Must be freed using free().
 *  \param[out] pcap_handle handle to pcap pipe (used if filename is "-"),
 *              if not writing to standard output it is set to INVALID_HANDLE_VALUE.
 *
 * \return BOOL TRUE on success, FALSE otherwise.
 */
/* Windows CRT argv escaping, not shell escaping. Bound every UTF-16 append
 * before allocation or writing; 32767 includes the terminating NUL. */
#define WORKER_COMMAND_CAPACITY 32767U
static BOOL worker_put(PWSTR buffer, size_t *used, WCHAR ch)
{
    if (*used >= WORKER_COMMAND_CAPACITY - 1)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }
    if (buffer != NULL) buffer[*used] = ch;
    ++*used;
    return TRUE;
}

static BOOL worker_text(PWSTR buffer, size_t *used, PCWSTR text)
{
    while (*text)
    {
        if (!worker_put(buffer, used, *text++)) return FALSE;
    }
    return TRUE;
}

static BOOL worker_quote(PWSTR buffer, size_t *used, PCWSTR text)
{
    size_t slashes;
    size_t i;
    if (!worker_put(buffer, used, L'"')) return FALSE;
    for (;;)
    {
        slashes = 0;
        while (*text == L'\\') { ++slashes; ++text; }
        /* Backslashes before a quote or the closing quote must be doubled. */
        for (i = 0; i < slashes; ++i)
        {
            if (!worker_put(buffer, used, L'\\')) return FALSE;
            if ((*text == L'"' || *text == L'\0') &&
                !worker_put(buffer, used, L'\\')) return FALSE;
        }
        if (*text == L'\0') break;
        if (*text == L'"' && !worker_put(buffer, used, L'\\')) return FALSE;
        if (!worker_put(buffer, used, *text++)) return FALSE;
    }
    return worker_put(buffer, used, L'"');
}

static PWSTR worker_widen(const char *text)
{
    int count;
    PWSTR wide;
    if (text == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    count = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    if (count <= 0) return NULL;
    if ((unsigned int)count > WORKER_COMMAND_CAPACITY)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return NULL;
    }
    wide = (PWSTR)malloc((size_t)count * sizeof(WCHAR));
    if (wide == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (MultiByteToWideChar(CP_ACP, 0, text, -1, wide, count) != count)
    {
        DWORD error = GetLastError();
        free(wide);
        SetLastError(error ? error : ERROR_NO_UNICODE_TRANSLATION);
        return NULL;
    }
    return wide;
}

static BOOL worker_parameters(struct thread_data *data, PCWSTR device,
                               PCWSTR output, PCWSTR addresses,
                               PWSTR buffer, size_t *used)
{
    WCHAR number[11]; /* UINT32 decimal digits plus NUL. */
    if (!worker_text(buffer, used, L"-d ") ||
        !worker_quote(buffer, used, device) ||
        !worker_text(buffer, used, L" -b ")) return FALSE;
    if (swprintf_s(number, _countof(number), L"%u", data->bufferlen) < 0 ||
        !worker_text(buffer, used, number) ||
        !worker_text(buffer, used, L" -o ") ||
        !worker_quote(buffer, used, output)) return FALSE;
    if (data->snaplen != DEFAULT_SNAPSHOT_LENGTH)
    {
        if (swprintf_s(number, _countof(number), L"%u", data->snaplen) < 0 ||
            !worker_text(buffer, used, L" -s ") ||
            !worker_text(buffer, used, number)) return FALSE;
    }
    if (addresses != NULL &&
        (!worker_text(buffer, used, L" --devices ") ||
         !worker_quote(buffer, used, addresses))) return FALSE;
    if (data->capture_all && !worker_text(buffer, used, L" --capture-from-all-devices")) return FALSE;
    if (data->capture_new && !worker_text(buffer, used, L" --capture-from-new-devices")) return FALSE;
    if (data->inject_descriptors && !worker_text(buffer, used, L" --inject-descriptors")) return FALSE;
    return TRUE;
}

static BOOL generate_worker_command_line(struct thread_data *data,
                                         PWSTR *appPath,
                                         PWSTR *appCmdLine,
                                         HANDLE *pcap_handle)
{
    PWSTR exePath = NULL;
    PWSTR cmdLine = NULL;
    PWSTR pipeName = NULL;
    PWSTR device = NULL;
    PWSTR output = NULL;
    PWSTR addresses = NULL;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    int exePathLen;
    int actualLength;
    size_t used = 0;
    size_t count;
    size_t i;
    DWORD error;
    const WCHAR prefix[] = L"\\\\.\\pipe\\";

    *appPath = NULL;
    *appCmdLine = NULL;
    *pcap_handle = INVALID_HANDLE_VALUE;
    exePathLen = GetModuleFullName(NULL, NULL, 0, NULL);
    if (exePathLen <= 0 || (unsigned int)exePathLen > WORKER_COMMAND_CAPACITY) goto failed;
    exePath = (PWSTR)malloc((size_t)exePathLen * sizeof(WCHAR));
    if (exePath == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto failed; }
    actualLength = GetModuleFullName(NULL, exePath, exePathLen, NULL);
    if (actualLength <= 0 || actualLength >= exePathLen) goto failed;
    device = worker_widen(data->device);
    output = worker_widen(data->filename);
    if (device == NULL || output == NULL) goto failed;
    if (data->address_list != NULL)
    {
        addresses = worker_widen(data->address_list);
        if (addresses == NULL) goto failed;
    }
    if (strcmp(data->filename, "-") == 0)
    {
        count = wcslen(device) + _countof(prefix);
        if (count > WORKER_COMMAND_CAPACITY) { SetLastError(ERROR_BUFFER_OVERFLOW); goto failed; }
        pipeName = (PWSTR)malloc(count * sizeof(WCHAR));
        if (pipeName == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto failed; }
        memcpy(pipeName, prefix, sizeof(prefix) - sizeof(WCHAR));
        memcpy(pipeName + _countof(prefix) - 1, device, (wcslen(device) + 1) * sizeof(WCHAR));
        for (i = _countof(prefix) - 1; pipeName[i]; ++i)
        {
            if (pipeName[i] == L'\\') pipeName[i] = L'_';
        }
    }
    if (!worker_parameters(data, device, pipeName ? pipeName : output, addresses, NULL, &used)) goto failed;
    count = used + 1;
    /* Account for quoted argv[0], space and NUL in the CreateProcess sibling. */
    if (count > WORKER_COMMAND_CAPACITY - 3 ||
        wcslen(exePath) > WORKER_COMMAND_CAPACITY - count - 3)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        goto failed;
    }
    cmdLine = (PWSTR)malloc(count * sizeof(WCHAR));
    if (cmdLine == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto failed; }
    used = 0;
    if (!worker_parameters(data, device, pipeName ? pipeName : output, addresses, cmdLine, &used)) goto failed;
    cmdLine[used] = L'\0';
    /* Create the pipe only after every fallible allocation/conversion. */
    if (pipeName != NULL)
    {
        pipe = CreateNamedPipeW(pipeName,
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                2, data->bufferlen, data->bufferlen, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) goto failed;
    }
    free(device);
    free(output);
    free(addresses);
    free(pipeName);
    *appPath = exePath;
    *appCmdLine = cmdLine;
    *pcap_handle = pipe;
    return TRUE;
failed:
    error = GetLastError();
    free(exePath);
    free(cmdLine);
    free(device);
    free(output);
    free(addresses);
    free(pipeName);
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    SetLastError(error ? error : ERROR_INVALID_DATA);
    return FALSE;
}
/**
 *  Creates elevated worker process.
 *
 *  \param[in] appPath path to elevated worker module
 *  \param[in] cmdLine commandline to start elevated worker with
 *
 *  \return Handle to created process.
 */
static HANDLE create_elevated_worker(PWSTR appPath, PWSTR cmdLine)
{
    BOOL bSuccess = FALSE;
    SHELLEXECUTEINFOW exInfo = { 0 };

    exInfo.cbSize = sizeof(exInfo);
    exInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    exInfo.hwnd = NULL;
    exInfo.lpVerb = L"runas";
    exInfo.lpFile = appPath;
    exInfo.lpParameters = cmdLine;
    exInfo.lpDirectory = NULL;
    exInfo.nShow = SW_HIDE;
    /* exInfo.hInstApp is output parameter */
    /* exInfo.lpIDList, exInfo.lpClass, exInfo.hkeyClass, exInfo.dwHotKey, exInfo.DUMMYUNIONNAME
     * are ignored for our fMask value.
     */
    /* exInfo.hProcess is output parameter */

    bSuccess = ShellExecuteExW(&exInfo);

    if (FALSE == bSuccess)
    {
        fprintf(stderr, "Failed to create worker process!\n");
        return INVALID_HANDLE_VALUE;
    }

    return exInfo.hProcess;
}

/**
 *  Creates intermediate worker process that creates elevated worker process
 *  inside a job that will terminate all processes on close.
 *
 *  On success it modifies data->worker_process_thread handle.
 *
 *  \param[inout] data thread_data containing capture configuration.
 *  \param[in] appPath path to elevated worker module
 *  \param[in] cmdLine commandline to start elevated worker with
 *
 *  \return Handle to created process.
 */
static HANDLE create_breakaway_worker_in_job(struct thread_data *data, PWSTR appPath, PWSTR appCmdLine)
{
    HANDLE process = INVALID_HANDLE_VALUE;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    PWSTR processCmdLine;
    size_t nChars;
    BOOL worker_failed = FALSE;

    if (data->job_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "create_breakaway_worker_in_job() cannot be called if data->job_handle is INVALID_HANDLE_VALUE!\n");
        return INVALID_HANDLE_VALUE;
    }

    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    /* CreateProcessW works different to ShellExecuteExW.
     * It will always treat first token of command line as argv[0] in
     * created process.
     *
     * Hence create new string that will contain "appPath" appCmdLine.
     */
    /* Check lengths before adding, and reject invalid argv[0] quoting. */
    if (appPath == NULL || appCmdLine == NULL || wcschr(appPath, L'\"') != NULL ||
        wcslen(appPath) > WORKER_COMMAND_CAPACITY - 4 ||
        wcslen(appCmdLine) > WORKER_COMMAND_CAPACITY - 4 - wcslen(appPath))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return INVALID_HANDLE_VALUE;
    }
    nChars = wcslen(appPath) + wcslen(appCmdLine) +
             4 /* Two quotemarks, one space and NULL-terminator */;
    processCmdLine = (PWSTR)malloc(nChars * sizeof(WCHAR));
    if (processCmdLine == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for processCmdLine!\n");
        return INVALID_HANDLE_VALUE;
    }

    if (swprintf_s(processCmdLine, nChars, L"\"%s\" %s",
                   appPath, appCmdLine) < 0)
    {
        free(processCmdLine);
        SetLastError(ERROR_INVALID_DATA);
        return INVALID_HANDLE_VALUE;
    }

    /* We need to breakaway from parent job and assign to data->job_handle. */
    if (0 == CreateProcessW(NULL, processCmdLine, NULL, NULL, FALSE,
                            CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
                            NULL, NULL, &startupInfo, &processInfo))
    {
        data->process = FALSE;
    }
    else
    {
        process = processInfo.hProcess;
        /* processInfo.hThread needs to be closed. */
        data->worker_process_thread = processInfo.hThread;

        /* process is not assigned to any job. Assign it. */
        if (AssignProcessToJobObject(data->job_handle, process) == FALSE)
        {
            fprintf(stderr, "Failed to Assign process to job object - %d\n",
                    GetLastError());
            worker_failed = TRUE;
        }
        else if (ResumeThread(data->worker_process_thread) == (DWORD)-1)
        {
            fprintf(stderr, "Failed to resume worker process: %lu\n", GetLastError());
            worker_failed = TRUE;
        }

        if (worker_failed)
        {
            BOOL termination_requested = FALSE;
            DWORD joined;
            /* Keep both handles and the local process owner until a confirmed
             * process signal. A termination request is asynchronous; failure
             * must be retried rather than followed by an infinite active-child
             * wait. Permanent failure intentionally cannot complete cleanup. */
            do
            {
                if (!termination_requested)
                {
                    termination_requested = TerminateProcess(process, 1);
                    if (!termination_requested)
                    {
                        fprintf(stderr, "Failed to terminate suspended worker: %lu\n", GetLastError());
                    }
                }
                joined = WaitForSingleObject(process, 100);
                if (joined != WAIT_OBJECT_0)
                {
                    if (joined == WAIT_FAILED)
                    {
                        fprintf(stderr, "Suspended worker join failed; retaining ownership: %lu\n", GetLastError());
                    }
                    else if (joined != WAIT_TIMEOUT)
                    {
                        fprintf(stderr, "Unexpected suspended worker wait result; retaining ownership: %lu\n", joined);
                    }
                    Sleep(100);
                }
            } while (joined != WAIT_OBJECT_0);
            CloseHandle(process);
            CloseHandle(data->worker_process_thread);
            data->process = FALSE;
            process = INVALID_HANDLE_VALUE;
            data->worker_process_thread = INVALID_HANDLE_VALUE;
        }
    }

    free(processCmdLine);

    return process;
}

static BOOL replace_owned_argument(char **target, const char *text)
{
    char *copy;
    if (text == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    copy = _strdup(text);
    if (copy == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    free(*target);
    *target = copy;
    return TRUE;
}

int cmd_interactive(struct thread_data *data)
{
    int i = 0;
    int max_i;
    char buffer[INPUT_BUFFER_SIZE];
    BOOL finished;
    BOOL exit = FALSE;

    /* Detach from parent console window. Make sure to reopen stdout
     * and stderr as otherwise wide_print() does not corectly detect
     * console.
     */
    FreeConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    /* If we are running interactive then we should show console window.
     * We are not automatically allocated a console window because the
     * application type is set to windows. This prevents console
     * window from showing when USBPcapCMD is used as extcap.
     * Since extcap is recommended cmd.exe users will notice a slight
     * inconvenience that USBPcapCMD opens new window.
     *
     * Please note that is it impossible to get parent's cmd.exe stdin
     * handle if application type is not console. The difference is
     * that in case of console application cmd.exe waits until the
     * process finishes and in case of windows applications there is
     * no wait for process termination and the cmd.exe console immadietely
     * regains standard input functionality.
     */
    if (AllocConsole() == FALSE)
    {
        return -1;
    }

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    data->filename = NULL;
    data->capture_all = TRUE;
    data->inject_descriptors = TRUE;

    filters_initialize();
    if (usbpcapFilters == NULL)
    {
        fprintf(stderr, "Failed to enumerate filter control devices.\n");
        return -1;
    }
    if (usbpcapFilters[0] == NULL)
    {
        printf("No filter control devices are available.\n");

        if (is_usbpcap_upper_filter_installed() == FALSE)
        {
            printf("Please reinstall USBPcapDriver.\n");
            (void)getchar();
            filters_free();
            return -1;
        }

        printf("USBPcap UpperFilter entry appears to be present.\n"
               "Most likely you have not restarted your computer after installation.\n"
               "It is possible to restart all USB devices to get USBPcap working without reboot.\n"
               "\nWARNING:\n  Restarting all USB devices can result in data loss.\n"
               "  If you are unsure please answer 'n' and reboot in order to use USBPcap.\n\n");

        finished = FALSE;
        do
        {
            printf("Do you want to restart all USB devices (y, n)? ");
            if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
            {
                printf("Invalid input\n");
            }
            else
            {
                if (buffer[0] == 'y')
                {
                    finished = TRUE;
                    restart_all_usb_devices();
                    filters_free();
                    filters_initialize();
                    if (usbpcapFilters == NULL || usbpcapFilters[0] == NULL)
                    {
                        filters_free();
                        return -1;
                    }
                }
                else if (buffer[0] == 'n')
                {
                    filters_free();
                    return -1;
                }
            }
        } while (finished == FALSE);
    }

    printf("Following filter control devices are available:\n");
    while (usbpcapFilters[i] != NULL)
    {
        printf("%d %s\n", i+1, usbpcapFilters[i]->device);
        enumerate_print_usbpcap_interactive(usbpcapFilters[i]->device);
        i++;
    }

    max_i = i;

    finished = FALSE;
    do
    {
        printf("Select filter to monitor (q to quit): ");
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
        {
            printf("Invalid input\n");
        }
        else
        {
            if (buffer[0] == 'q')
            {
                finished = TRUE;
                exit = TRUE;
            }
            else
            {
                int value = atoi(buffer);

                if (value <= 0 || value > max_i)
                {
                    printf("Invalid input\n");
                }
                else
                {
                    if (!replace_owned_argument(&data->device, usbpcapFilters[value-1]->device))
                    {
                        filters_free();
                        return -1;
                    }
                    finished = TRUE;
                }
            }
        }
    } while (finished == FALSE);

    if (exit == TRUE)
    {
        filters_free();
        return -1;
    }

    finished = FALSE;
    do
    {
        printf("Output file name (.pcap): ");
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
        {
            printf("Invalid input\n");
        }
        else if (buffer[0] == '\0')
        {
            printf("Empty filename not allowed\n");
        }
        else
        {
            for (i = 0; i < INPUT_BUFFER_SIZE; i++)
            {
                if (buffer[i] == '\n')
                {
                    buffer[i] = '\0';
                    break;
                }
            }
            if (!replace_owned_argument(&data->filename, buffer))
            {
                filters_free();
                return -1;
            }
            finished = TRUE;
        }
    } while (finished == FALSE);

    filters_free();
    return 0;
}

/**
 * Wait for exit signal.
 *
 * Wait for either 'q' on standard input, data->exit_event or worker process termination.
 *
 * \param[in] data Thread data structure
 * \param[in] process Worker process handle
 *                    INVALID_HANDLE_VALUE if not using elevated worker.
 */
static void wait_for_exit_signal(struct thread_data *data, HANDLE process)
{
    HANDLE handle_table[3] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
    HANDLE stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD dw;
    int count = 0;
    DWORD console_mode;

    /* ReadConsoleInput requires console input; redirected EOF would spin. */
    if ((stdin_handle != NULL) && (stdin_handle != INVALID_HANDLE_VALUE) &&
        GetConsoleMode(stdin_handle, &console_mode))
    {
        dw = WaitForSingleObject(stdin_handle, 0);
        if (dw != WAIT_FAILED)
        {
            handle_table[count] = stdin_handle;
            count++;
        }
    }

    if ((data->exit_event != NULL) && (data->exit_event != INVALID_HANDLE_VALUE))
    {
        handle_table[count] = data->exit_event;
        count++;
    }

    if ((process != NULL) && (process != INVALID_HANDLE_VALUE))
    {
        handle_table[count] = process;
        count++;
    }

    if (count == 0)
    {
        fprintf(stderr, "Nothing to wait for in wait_for_exit_signal().\n");
        return;
    }

    /* Wait for exit condition. */
    while (InterlockedCompareExchange(&data->process, FALSE, FALSE) != FALSE)
    {
        dw = WaitForMultipleObjects(count, handle_table, FALSE, INFINITE);
#pragma warning(default : 4296)
        if (dw < (WAIT_OBJECT_0 + (DWORD)count))
        {
            int i = dw - WAIT_OBJECT_0;
            if (handle_table[i] == stdin_handle)
            {
                /* There is something new on standard input. */
                INPUT_RECORD record;
                DWORD events_read;

                if (ReadConsoleInput(stdin_handle, &record, 1, &events_read))
                {
                    if (record.EventType == KEY_EVENT)
                    {
                        if ((record.Event.KeyEvent.bKeyDown == TRUE) &&
                            (record.Event.KeyEvent.uChar.AsciiChar == 'q'))
                        {
                            /* There is 'q' on standard input. Quit. */
                            break;
                        }
                    }
                }
            }
            else if (handle_table[i] == process)
            {
                /* Elevated worker process terminated. Quit. */
                break;
            }
            else if (handle_table[i] == data->exit_event)
            {
                /* Read thread has finished. Quit. */
                break;
            }
        }
        else if (dw == WAIT_FAILED)
        {
            fprintf(stderr, "WaitForMultipleObjects failed in wait_for_exit_signal(): %d\n", GetLastError());
            break;
        }
    }
}

static HANDLE create_capture_output(struct thread_data *data)
{
    HANDLE handle;
    BOOL pipe = (_strnicmp(data->filename, "\\\\.\\pipe\\", 9) == 0);
    DWORD access = pipe ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_WRITE;
    data->write_handle_owned = FALSE;
    data->monitor_write_handle = FALSE;
    if (strncmp("-", data->filename, 2) == 0)
    {
        return GetStdHandle(STD_OUTPUT_HANDLE);
    }
    handle = CreateFileA(data->filename, access, 0, NULL,
                         pipe ? OPEN_EXISTING : CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if ((handle == INVALID_HANDLE_VALUE) && pipe && (GetLastError() == ERROR_ACCESS_DENIED))
    {
        /* Receive-only extcap pipes still work, without a read probe. */
        access = GENERIC_WRITE;
        handle = CreateFileA(data->filename, access, 0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    }
    if (handle != INVALID_HANDLE_VALUE)
    {
        data->write_handle_owned = TRUE;
        data->monitor_write_handle = pipe && ((access & GENERIC_READ) != 0);
    }
    return handle;
}

/* Called only after worker join; stdout remains owned by the CRT/caller. */
static void close_capture_handles(struct thread_data *data)
{
    if ((data->read_handle != NULL) && (data->read_handle != INVALID_HANDLE_VALUE))
    {
        CloseHandle(data->read_handle);
    }
    if (data->write_handle_owned && (data->write_handle != NULL) &&
        (data->write_handle != INVALID_HANDLE_VALUE))
    {
        CloseHandle(data->write_handle);
    }
    data->read_handle = INVALID_HANDLE_VALUE;
    data->write_handle = INVALID_HANDLE_VALUE;
    data->write_handle_owned = FALSE;
    data->monitor_write_handle = FALSE;
}

/* Return only after the owned process is signaled. The capture running flag
 * is not a child-lifetime flag: stopping capture does not authorize closing
 * process/thread/job handles. Permanent join failure keeps this call pending. */
static void wait_for_worker_process_exit(HANDLE process, BOOL terminate_worker)
{
    BOOL termination_requested = FALSE;
    DWORD joined;
    do
    {
        if (terminate_worker && !termination_requested)
        {
            termination_requested = TerminateProcess(process, 0);
            if (!termination_requested)
            {
                fprintf(stderr, "Failed to terminate worker; retaining ownership: %lu\n", GetLastError());
            }
        }
        joined = WaitForSingleObject(process, 100);
        if (joined != WAIT_OBJECT_0)
        {
            if (joined == WAIT_FAILED)
            {
                fprintf(stderr, "Worker join failed; retaining ownership: %lu\n", GetLastError());
            }
            else if (joined != WAIT_TIMEOUT)
            {
                fprintf(stderr, "Unexpected worker wait result; retaining ownership: %lu\n", joined);
            }
            Sleep(100);
        }
    } while (joined != WAIT_OBJECT_0);
}

static void start_capture(struct thread_data *data)
{
    HANDLE pipe_handle = INVALID_HANDLE_VALUE;
    HANDLE process = INVALID_HANDLE_VALUE;
    HANDLE thread = NULL;
    BOOL terminate_worker = FALSE;
    DWORD thread_id;

    data->read_handle = INVALID_HANDLE_VALUE;
    data->write_handle = INVALID_HANDLE_VALUE;
    data->write_handle_owned = FALSE;
    data->monitor_write_handle = FALSE;

    /* Sanity check capture configuration. */
    if ((data->capture_all == FALSE) &&
        (data->capture_new == FALSE) &&
        (data->address_list == NULL))
    {
        fprintf(stderr, "Selected capture options result in empty capture.\n");
        fprintf(stderr, "Add command-line option -A to capture from all devices.\n");
        return;
    }

    if (FALSE == USBPcapInitAddressFilter(&data->filter, data->address_list, data->capture_all))
    {
        fprintf(stderr, "USBPcapInitAddressFilter failed!\n");
        return;
    }

    data->exit_event = CreateEvent(NULL, /* Handle cannot be inherited */
                                   TRUE, /* Manual Reset */
                                   FALSE, /* Default to not signalled */
                                   NULL);

    if (data->exit_event == NULL)
    {
        fprintf(stderr, "Failed to create capture shutdown event: %lu\n", GetLastError());
        data->exit_event = INVALID_HANDLE_VALUE;
        InterlockedExchange(&data->process, FALSE);
        return;
    }

    memset(&data->descriptors, 0, sizeof(data->descriptors));

    if (IsElevated() == TRUE)
    {
        data->read_handle = INVALID_HANDLE_VALUE;
        data->write_handle = create_capture_output(data);
        if ((data->write_handle == NULL) || (data->write_handle == INVALID_HANDLE_VALUE))
        {
            fprintf(stderr, "Failed to open capture output: %lu\n", GetLastError());
            goto capture_finish;
        }

        if (data->inject_descriptors)
        {
            data->descriptors.descriptors = descriptors_generate_pcap(data->device, &data->descriptors.descriptors_len,
                                                                      &data->filter);
            if (data->descriptors.descriptors == NULL && GetLastError() != ERROR_SUCCESS)
            {
                fprintf(stderr, "Failed to prepare descriptor packets: %lu\n", GetLastError());
                goto capture_finish;
            }
            data->descriptors.buf_written = 0;
        }

        data->read_handle = create_filter_read_handle(data);
        if (data->read_handle == INVALID_HANDLE_VALUE)
        {
            goto capture_finish;
        }

        thread = CreateThread(NULL, /* default security attributes */
                              0,    /* use default stack size */
                              read_thread,
                              data,
                              0,    /* use default creation flag */
                              &thread_id);

        if (thread == NULL)
        {
            fprintf(stderr, "Failed to create thread\n");
            data->process = FALSE;
        }
    }
    else
    {
        PWSTR appPath = NULL;
        PWSTR appCmdLine = NULL;

        BOOL in_job = FALSE;

        if (FALSE == generate_worker_command_line(data, &appPath, &appCmdLine, &pipe_handle))
        {
            fprintf(stderr, "Failed to generate command line\n");
            data->process = FALSE;
        }
        else
        {
            /* Default state is USBPcapCMD running outside any job and hence
             * we need to create new job to take care of worker processes.
             */
            BOOL needs_breakaway = FALSE;
            BOOL needs_new_job = TRUE;

            /* We are not elevated. Check if we are running inside a job. */
            IsProcessInJob(GetCurrentProcess(), NULL, &in_job);

            if (in_job)
            {
                /* We are running inside a job. This can be Visual Studio debug session
                 * job or Windows 8.1 Wireshark job or USBPcap job or anything else.
                 *
                 * If the job has JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, then assume
                 * that whoever create the job will get care of any dangling processes.
                 *
                 * If the job has JOB_OBJECT_LIMIT_BREAKAWAY_OK (which is the case for
                 * Visual Studio and Windows 8.1 jobs) then we need to create intermediate
                 * worker to launch elevated worker. The intermediate worker needs to
                 * break from parent job.
                 *
                 * If the job has JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK we could omit
                 * the intermediate worker, but keep it there so there's no race condion
                 * (if parent gets terminated after executing elevated worker but before
                 * the elevated worker is assigned to a job, then the elevated worker
                 * will need to be manually terminated). If we are not running inside
                 * a job this race condition is not a problem because we first assign
                 * our process to a job (and hence all newly created processes are
                 * automatically assigned to that job).
                 *
                 *
                 * All this is because ShellExecuteEx() does not support
                 * CREATE_BREAKAWAY_FROM_JOB nor CREATE_SUSPENDED flags.
                 * CreateProcess() supports CREATE_BREAKAWAY_FROM_JOB and CREATE_SUSPENDED
                 * flag but do not support "runas" option. USBPcapCMD manifest does not
                 * require administrator access because that would result in UAC screen
                 * every time Wireshark gets extcap interface options.
                 */

                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;

                memset(&info, 0, sizeof(info));
                if (0 == QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation,
                                                   &info, sizeof(info), NULL))
                {
                    fprintf(stderr, "Failed to query job information - %d\n", GetLastError());
                    /* This is fatal error. */
                    data->process = FALSE;
                    goto worker_cleanup;
                }

                if (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                {
                    /* There is no need to breakaway nor to create new job. */
                    needs_breakaway = FALSE;
                    needs_new_job = FALSE;
                }
                else if (info.BasicLimitInformation.LimitFlags &
                         (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))
                {
                   needs_breakaway = TRUE;
                   needs_new_job = TRUE;
                }
                else
                {
                    fprintf(stderr, "Unhandled job limit flags 0x%08X\n", info.BasicLimitInformation.LimitFlags);
                    /* This is not fatal. We cannot perform job breakaway though! */
                    needs_breakaway = FALSE;
                    needs_new_job = FALSE;
                }
            }

            if (needs_new_job)
            {
                if (data->job_handle == INVALID_HANDLE_VALUE)
                {
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;

                    data->job_handle = CreateJobObject(NULL, NULL);
                    if (data->job_handle == NULL)
                    {
                        fprintf(stderr, "Failed to create job object!\n");
                        data->process = FALSE;
                        data->job_handle = INVALID_HANDLE_VALUE;
                        goto worker_cleanup;
                    }

                    memset(&info, 0, sizeof(info));
                    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    if (!SetInformationJobObject(data->job_handle, JobObjectExtendedLimitInformation, &info, sizeof(info)))
                    {
                        fprintf(stderr, "Failed to configure worker job: %lu\n", GetLastError());
                        data->process = FALSE;
                        goto worker_cleanup;
                    }
                }

                /* If breakaway is not needed for worker process, then assign ourselves to newly created job.
                 * This will result in automatic worker process assignment to newly created job.
                 */
                if (needs_breakaway == FALSE)
                {
                    if (AssignProcessToJobObject(data->job_handle, GetCurrentProcess()) == FALSE)
                    {
                        fprintf(stderr, "Failed to Assign process to job object - %d\n",
                                GetLastError());
                        /* This is fatal error. */
                        data->process = FALSE;
                        goto worker_cleanup;
                    }
                }
            }

            if (needs_breakaway == FALSE)
            {
                /* Create elevated worker process. It will automatically be assigned to proper job. */
                process = create_elevated_worker(appPath, appCmdLine);
            }
            else
            {
                process = create_breakaway_worker_in_job(data, appPath, appCmdLine);
            }

worker_cleanup:
            /* Free worker path and command line strings as these are no longer needed. */
            free(appPath);
            free(appCmdLine);
            appPath = NULL;
            appCmdLine = NULL;

            if (process != INVALID_HANDLE_VALUE)
            {
                if (strncmp("-", data->filename, 2) == 0)
                {
                    data->write_handle = GetStdHandle(STD_OUTPUT_HANDLE);
                    data->read_handle = pipe_handle;

                    thread = CreateThread(NULL, /* default security attributes */
                                          0,    /* use default stack size */
                                          read_thread,
                                          data,
                                          0,    /* use default creation flag */
                                          &thread_id);
                    pipe_handle = INVALID_HANDLE_VALUE; /* ownership transferred */
                    if (thread == NULL)
                    {
                        fprintf(stderr, "Failed to create relay thread: %lu\n", GetLastError());
                        data->process = FALSE;
                    }
                }
                else
                {
                    /* Worker process saves directly to file */
                    data->write_handle = INVALID_HANDLE_VALUE;
                    data->read_handle = INVALID_HANDLE_VALUE;
                }
            }
            else
            {
                /* Worker couldn't be started. */
                data->process = FALSE;
                if (pipe_handle != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(pipe_handle);
                    pipe_handle = INVALID_HANDLE_VALUE;
                }
            }
        }
    }

    wait_for_exit_signal(data, process);
capture_finish:
    request_capture_stop(data);

    /* If we created worker thread, wait for it to terminate. */
    if (thread != NULL)
    {
        stop_capture_thread(data, thread);
        CloseHandle(thread);
    }

    /* Closing read and write handles will terminate worker process. */

    if ((data->read_handle == INVALID_HANDLE_VALUE) &&
        (data->write_handle == INVALID_HANDLE_VALUE))
    {
        /* We should kill worker process if we created it.
         * We have no other way to let process know that it needs to quit.
         */
        if (process != INVALID_HANDLE_VALUE)
        {
            terminate_worker = TRUE;
        }
    }

    close_capture_handles(data);
    if (pipe_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe_handle);
    }

    /* If we created worker process, wait for it to terminate. */
    if (process != INVALID_HANDLE_VALUE)
    {
        wait_for_worker_process_exit(process, terminate_worker);
        CloseHandle(process);
        process = INVALID_HANDLE_VALUE;
        if (data->worker_process_thread != INVALID_HANDLE_VALUE)
        {
            CloseHandle(data->worker_process_thread);
            data->worker_process_thread = INVALID_HANDLE_VALUE;
        }
    }

    if (data->descriptors.descriptors)
    {
        descriptors_free_pcap(data->descriptors.descriptors);
        data->descriptors.descriptors = NULL;
        data->descriptors.descriptors_len = 0;
    }
}

static void print_extcap_version(void)
{
    printf("extcap {version=" USBPCAPCMD_VERSION_STR "}{help=http://desowin.org/usbpcap/}\n");
}

static void print_extcap_interfaces(void)
{
    int i = 0;
    filters_initialize();
    if (usbpcapFilters == NULL)
    {
        fprintf(stderr, "Failed to enumerate extcap interfaces.\n");
        return;
    }

    while (usbpcapFilters[i] != NULL)
    {
        char *tmp = strrchr(usbpcapFilters[i]->device, '\\');
        if (tmp == NULL)
        {
            tmp = usbpcapFilters[i]->device;
        }
        else
        {
            tmp++;
        }

        printf("interface {value=%s}{display=%s}\n",
               usbpcapFilters[i]->device, tmp);
        i++;
    }

    filters_free();
}

static void print_extcap_dlts(void)
{
    printf("dlt {number=249}{name=USBPCAP}{display=USBPcap}\n");
}

static int print_extcap_options(const char *device)
{
    if (device == NULL)
    {
        return -1;
    }

    printf("arg {number=0}{call=--snaplen}"
           "{display=Snapshot length}{tooltip=Snapshot length}"
           "{type=unsigned}{default=%d}\n", DEFAULT_SNAPSHOT_LENGTH);
    printf("arg {number=1}{call=--bufferlen}"
           "{display=Capture buffer length}"
           "{tooltip=USBPcap kernel-mode capture buffer length in bytes}"
           "{type=integer}{range=0,134217728}{default=%d}\n",
           DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE);
    printf("arg {number=2}{call=--capture-from-all-devices}"
           "{display=Capture from all devices connected}"
           "{tooltip=Capture from all devices connected despite other options}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=3}{call=--capture-from-new-devices}"
           "{display=Capture from newly connected devices}"
           "{tooltip=Automatically start capture on all newly connected devices}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=4}{call=--inject-descriptors}"
           "{display=Inject already connected devices descriptors into capture data}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=%d}{call=--devices}{display=Attached USB Devices}{tooltip=Select individual devices to capture from}{type=multicheck}\n",
           EXTCAP_ARGNUM_MULTICHECK);

    enumerate_print_extcap_config(device);

    return 0;
}

static int run_as_extcap = 0;
static int do_extcap_version = 0;
static int do_extcap_interfaces = 0;
static int do_extcap_dlts = 0;
static int do_extcap_config = 0;
static int do_extcap_capture = 0;
static const char *wireshark_version = NULL;
static const char *extcap_interface = NULL;
static const char *extcap_fifo = NULL;

int cmd_extcap(struct thread_data *data)
{
    int ret = -1;

    if (do_extcap_version)
    {
        print_extcap_version();
        ret = 0;
    }

    if (do_extcap_interfaces)
    {
        print_extcap_interfaces();
        ret = 0;
    }

    if (do_extcap_dlts)
    {
        print_extcap_dlts();
        ret = 0;
    }

    if (do_extcap_config)
    {
        ret = print_extcap_options(extcap_interface);
    }

    /* --capture */
    if (do_extcap_capture)
    {
        if ((extcap_fifo == NULL) || (extcap_interface == NULL))
        {
            /* No fifo nor interface to capture from. */
            return -1;
        }

        if (!replace_owned_argument(&data->device, extcap_interface) ||
            !replace_owned_argument(&data->filename, extcap_fifo))
        {
            return -1;
        }
        data->process = TRUE;

        data->read_handle = INVALID_HANDLE_VALUE;
        data->write_handle = INVALID_HANDLE_VALUE;

        start_capture(data);
        return 0;
    }

    return ret;
}

BOOLEAN IsHandleRedirected(DWORD handle)
{
    HANDLE h = GetStdHandle(handle);
    if (h)
    {
        BY_HANDLE_FILE_INFORMATION fi;
        if (GetFileInformationByHandle(h, &fi))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static void attach_parent_console()
{
    HANDLE inHandle, outHandle, errHandle;
    BOOL outRedirected, errRedirected;

    inHandle = GetStdHandle(STD_INPUT_HANDLE);
    outHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    errHandle = GetStdHandle(STD_ERROR_HANDLE);

    outRedirected = IsHandleRedirected(STD_OUTPUT_HANDLE);
    errRedirected = IsHandleRedirected(STD_ERROR_HANDLE);

    if (outRedirected && errRedirected)
    {
        /* Both standard output and error handles are redirected.
         * There is no point in attaching to parent process console.
         */
        return;
    }

    if (AttachConsole(ATTACH_PARENT_PROCESS) == 0)
    {
        /* Console attach failed. */
        return;
    }

    if (inHandle != GetStdHandle(STD_INPUT_HANDLE))
    {
        /* Restore input handle. */
        SetStdHandle(STD_INPUT_HANDLE, inHandle);
    }

    /* Console attach succeded */
    if (outRedirected == FALSE)
    {
        freopen("CONOUT$", "w", stdout);
    }
    else if (GetStdHandle(STD_OUTPUT_HANDLE) != outHandle)
    {
        /* Attach Console changed STD_OUTPUT_HANDLE even though it is redirected.
         * Restore the redirected handle.
         */
        SetStdHandle(STD_OUTPUT_HANDLE, outHandle);
    }

    if (errRedirected == FALSE)
    {
        freopen("CONOUT$", "w", stderr);
    }
    else if (GetStdHandle(STD_ERROR_HANDLE) != errHandle)
    {
        /* Attach Console changed STD_ERROR_HANDLE even though it is redirected.
         * Restore the redirected handle.
         */
        SetStdHandle(STD_ERROR_HANDLE, errHandle);
    }
}

static void print_help(void)
{
    printf("Usage: USBPcapCMD.exe [options]\n"
           "  -h, -?, --help\n"
           "    Prints this help.\n"
           "  -d <device>, --device <device>\n"
           "    USBPcap control device to open. Example: -d \\\\.\\USBPcap1.\n"
           "  -o <file>, --output <file>\n"
           "    Output .pcap file name.\n"
           "  -s <len>, --snaplen <len>\n"
           "    Sets snapshot length.\n"
           "  -b <len>, --bufferlen <len>\n"
           "    Sets internal capture buffer length. Valid range <4096,134217728>.\n"
           "  -A, --capture-from-all-devices\n"
           "    Captures data from all devices connected to selected Root Hub.\n"
           "  --devices <list>\n"
           "    Captures data only from devices with addresses present in list.\n"
           "    List is comma separated list of values. Example --devices 1,2,3.\n"
           "  --inject-descriptors\n"
           "    Inject already connected devices descriptors into capture data.\n"
           "  -I,  --init-non-standard-hwids\n"
           "    Initializes NonStandardHWIDs registry key used by USBPcapDriver.\n"
           "    This registry key is needed for USB 3.0 capture.\n");
}

/* Commandline arguments without short option */
#define ARG_DEVICES                    900
#define ARG_CAPTURE_FROM_NEW_DEVICES   901
#define ARG_INJECT_DESCRIPTORS         902
#define ARG_EXTCAP_VERSION            1000
#define ARG_EXTCAP_INTERFACES         1001
#define ARG_EXTCAP_INTERFACE          1002
#define ARG_EXTCAP_DLTS               1003
#define ARG_EXTCAP_CONFIG             1004
#define ARG_EXTCAP_CAPTURE            1005
#define ARG_EXTCAP_FIFO               1006

#if _MSC_VER >= 1700
int __cdecl usbpcapcmd_main(int argc, CHAR **argv)
#else
int __cdecl main(int argc, CHAR **argv)
#endif
{
    int ret = -1;
    struct thread_data data;
    static struct option long_options[] =
    {
        {"help", no_argument, 0, 'h'},
        {"device", required_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"snaplen", required_argument, 0, 's'},
        {"bufferlen", required_argument, 0, 'b'},
        {"init-non-standard-hwids", no_argument, 0, 'I'},
        /* Capture options. */
        {"devices", required_argument, 0, ARG_DEVICES},
        {"capture-from-all-devices", no_argument, 0, 'A'},
        {"capture-from-new-devices", no_argument, 0, ARG_CAPTURE_FROM_NEW_DEVICES},
        {"inject-descriptors", no_argument, 0, ARG_INJECT_DESCRIPTORS},
        /* Extcap interface. Please note that there are no short
         * options for these and the numbers are just gopt keys.
         */
        {"extcap-version", optional_argument, 0, ARG_EXTCAP_VERSION},
        {"extcap-interfaces", no_argument, &do_extcap_interfaces, ARG_EXTCAP_INTERFACES},
        {"extcap-interface", required_argument, 0, ARG_EXTCAP_INTERFACE},
        {"extcap-dlts", no_argument, &do_extcap_dlts, ARG_EXTCAP_DLTS},
        {"extcap-config", no_argument, &do_extcap_config, ARG_EXTCAP_CONFIG},
        {"capture", no_argument, &do_extcap_capture, ARG_EXTCAP_CAPTURE},
        {"fifo", required_argument, 0, ARG_EXTCAP_FIFO},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    int c;

    attach_parent_console();

    data.filename = NULL;
    data.device = NULL;
    data.address_list = NULL;
    data.capture_all = FALSE;
    data.capture_new = FALSE;
    data.inject_descriptors = FALSE;
    data.snaplen = DEFAULT_SNAPSHOT_LENGTH;
    data.bufferlen = DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE;
    data.job_handle = INVALID_HANDLE_VALUE;
    data.worker_process_thread = INVALID_HANDLE_VALUE;
    data.read_handle = INVALID_HANDLE_VALUE;
    data.write_handle = INVALID_HANDLE_VALUE;
    data.write_handle_owned = FALSE;
    data.monitor_write_handle = FALSE;
    data.exit_event = INVALID_HANDLE_VALUE;

    while (-1 != (c = getopt_long(argc, argv, "hd:o:s:b:IA", long_options, &option_index)))
    {
        switch (c)
        {
            case 0:
                /* getopt_long has set the flag. */
                break;
            case 'h': /* --help */
                print_help();
                return 0;
            case 'd': /* --device */
#pragma warning(push)
#pragma warning(disable:28193)
                if (!replace_owned_argument(&data.device, optarg)) goto cmd_cleanup;
#pragma warning(pop)
                break;
            case 'o': /* --output */
#pragma warning(push)
#pragma warning(disable:28193)
                if (!replace_owned_argument(&data.filename, optarg)) goto cmd_cleanup;
#pragma warning(pop)
                break;
            case 's': /* --snaplen */
                data.snaplen = atol(optarg);
                if (data.snaplen == 0)
                {
                    fprintf(stderr, "Invalid snapshot length!\n");
                    return -1;
                }
                break;
            case 'b': /* --bufferlen */
                data.bufferlen = atol(optarg);
                /* Minimum buffer size if 4 KiB, maximum 128 MiB */
                if (data.bufferlen < 4096 || data.bufferlen > 134217728)
                {
                    fprintf(stderr, "Invalid buffer length! "
                                    "Valid range <4096,134217728>.\n");
                    return -1;
                }
                break;
            case 'I': /* --init-non-standard-hwids */
                init_non_standard_roothub_hwid();
                return 0;
            case ARG_DEVICES:
                data.address_list = optarg;
                break;
            case 'A': /* --capture-from-all-devices */
                data.capture_all = TRUE;
                break;
            case ARG_CAPTURE_FROM_NEW_DEVICES:
                data.capture_new = TRUE;
                break;
            case ARG_INJECT_DESCRIPTORS:
                data.inject_descriptors = TRUE;
                break;
            case ARG_EXTCAP_VERSION:
                do_extcap_version = 1;
                wireshark_version = optarg;
                break;
            case ARG_EXTCAP_INTERFACE:
                extcap_interface = optarg;
                break;
            case ARG_EXTCAP_FIFO:
                run_as_extcap = 1;
                extcap_fifo = optarg;
                break;

            case ':':
            case '?':
                fprintf(stderr, "Try 'USBPcapCMD.exe --help' for more information.\n");
                return -1;

            default:
                printf("getopt_long() returned character code 0x%X. Please report.\n", c);
                return -1;
        }
    }

    if (data.snaplen > (data.bufferlen - sizeof(pcaprec_hdr_t)))
    {
        fprintf(stderr, "Packets larger than %zu bytes won't be captured due to too small buffer.\n",
                data.bufferlen - sizeof(pcaprec_hdr_t));
    }

    /* Handle extcap options separately from standard USBPcapCMD options. */
    if (run_as_extcap || do_extcap_version || do_extcap_interfaces || do_extcap_dlts || do_extcap_config || do_extcap_capture)
    {
        ret = cmd_extcap(&data);
    }
    else
    {
        ret = 0;

        if ((data.filename == NULL) || (data.device == NULL))
        {
            if (data.filename != NULL)
            {
                free(data.filename);
                data.filename = NULL;
            }

            if (data.device != NULL)
            {
                free(data.device);
                data.device = NULL;
            }

            ret = cmd_interactive(&data);
        }

        if (ret == 0)
        {
            data.process = TRUE;
            start_capture(&data);
        }
    }

cmd_cleanup:
    /* Clean up */
    if (data.device != NULL)
    {
        free(data.device);
    }
    if (data.filename != NULL)
    {
        free(data.filename);
    }
    if (data.worker_process_thread != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.worker_process_thread);
    }
    if (data.job_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.job_handle);
    }
    if (data.exit_event != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.exit_event);
    }

    return ret;
}

#if _MSC_VER >= 1700
int CALLBACK WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine,
                     int nCmdShow)
{
    return usbpcapcmd_main(__argc, __argv);
}
#endif
