/*
 * Copyright (c) 2013 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <windows.h>
#include <devioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wtypes.h>
#include "USBPcap.h"
#include "thread.h"
#include "iocontrol.h"
#include "descriptors.h"

void request_capture_stop(struct thread_data *data)
{
    InterlockedExchange(&data->process, FALSE);
    if ((data->exit_event != NULL) && (data->exit_event != INVALID_HANDLE_VALUE))
    {
        if (!SetEvent(data->exit_event))
        {
            fprintf(stderr, "Failed to signal capture shutdown: %lu\n", GetLastError());
        }
    }
}

BOOL capture_running(struct thread_data *data)
{
    DWORD dw;
    if (InterlockedCompareExchange(&data->process, FALSE, FALSE) == FALSE)
    {
        return FALSE;
    }
    dw = WaitForSingleObject(data->exit_event, 0);
    if (dw == WAIT_TIMEOUT)
    {
        return TRUE;
    }
    if (dw == WAIT_FAILED)
    {
        fprintf(stderr, "Failed to check capture shutdown: %lu\n", GetLastError());
    }
    request_capture_stop(data);
    return FALSE;
}

/* Cancellation is a request, never a completion/ownership transfer.  On a
 * failed wait, retain storage if Internal still indicates STATUS_PENDING.
 * The owner keeps both handle and event open until terminal completion. */
static BOOL complete_io(HANDLE handle, LPOVERLAPPED overlapped,
                        DWORD *bytes, BOOL *active, BOOL wait)
{
    BOOL success = GetOverlappedResult(handle, overlapped, bytes, wait);
    DWORD err = success ? ERROR_SUCCESS : GetLastError();
    if (success || ((err != ERROR_IO_INCOMPLETE) && (err != ERROR_IO_PENDING) &&
                    HasOverlappedIoCompleted(overlapped)))
    {
        *active = FALSE;
    }
    SetLastError(err);
    return success;
}

static void drain_io(HANDLE handle, LPOVERLAPPED overlapped, BOOL *active)
{
    DWORD bytes = 0;
    DWORD err;
    if (!*active)
    {
        return;
    }
    if (!CancelIoEx(handle, overlapped))
    {
        err = GetLastError();
        if (err != ERROR_NOT_FOUND)
        {
            fprintf(stderr, "CancelIoEx failed: %lu; waiting for I/O rundown.\n", err);
        }
    }
    while (*active)
    {
        if (!complete_io(handle, overlapped, &bytes, active, TRUE))
        {
            err = GetLastError();
            if (*active)
            {
                /* A failed wait is not proof that the request has completed. */
                Sleep(1);
            }
            else if (err != ERROR_OPERATION_ABORTED)
            {
                fprintf(stderr, "I/O rundown completed with error: %lu\n", err);
            }
        }
    }
}

void stop_capture_thread(struct thread_data *data, HANDLE thread)
{
    DWORD dw;
    DWORD err;
    BOOL reported = FALSE;
    request_capture_stop(data);
    for (;;)
    {
        dw = WaitForSingleObject(thread, 100);
        if (dw == WAIT_OBJECT_0)
        {
            return;
        }
        if ((dw == WAIT_FAILED) && !reported)
        {
            fprintf(stderr, "Worker join failed: %lu; retaining capture resources.\n", GetLastError());
            reported = TRUE;
        }
        /* Borrowed stdout and FlushFileBuffers can perform synchronous I/O.
         * Retry until join, including the stop-check/WriteFile issuance race. */
        if (!CancelSynchronousIo(thread))
        {
            err = GetLastError();
            if ((err != ERROR_NOT_FOUND) && !reported)
            {
                fprintf(stderr, "CancelSynchronousIo failed: %lu\n", err);
                reported = TRUE;
            }
        }
        if (dw == WAIT_FAILED)
        {
            Sleep(100);
        }
    }
}

static BOOL filter_ioctl(HANDLE handle, DWORD code, void *buffer, DWORD size)
{
    OVERLAPPED overlapped = {0};
    DWORD bytes = 0;
    DWORD err;
    BOOL success;
    BOOL active = FALSE;
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL)
    {
        return FALSE;
    }
    success = DeviceIoControl(handle, code, buffer, size, NULL, 0, &bytes, &overlapped);
    err = success ? ERROR_SUCCESS : GetLastError();
    if (!success && (err == ERROR_IO_PENDING))
    {
        active = TRUE;
        success = complete_io(handle, &overlapped, &bytes, &active, TRUE);
        err = success ? ERROR_SUCCESS : GetLastError();
        drain_io(handle, &overlapped, &active);
    }
    CloseHandle(overlapped.hEvent);
    SetLastError(err);
    return success;
}

HANDLE create_filter_read_handle(struct thread_data *data)
{
    HANDLE filter_handle = INVALID_HANDLE_VALUE;
    USBPCAP_IOCTL_SIZE size;

    if (data->capture_new)
    {
        USBPcapSetDeviceFiltered(&data->filter, 0);
    }

    filter_handle = CreateFileA(data->device,
                                GENERIC_READ|GENERIC_WRITE,
                                0,
                                0,
                                OPEN_EXISTING,
                                FILE_FLAG_OVERLAPPED,
                                0);

    if (filter_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Couldn't open device - %d\n", GetLastError());
        goto finish;
    }

    size.size = data->snaplen;
    if (!filter_ioctl(filter_handle, IOCTL_USBPCAP_SET_SNAPLEN_SIZE, &size, sizeof(size)))
    {
        fprintf(stderr, "Set snapshot length failed: %lu\n", GetLastError());
        goto finish;
    }

    size.size = data->bufferlen;
    if (!filter_ioctl(filter_handle, IOCTL_USBPCAP_SETUP_BUFFER, &size, sizeof(size)))
    {
        fprintf(stderr, "Set capture buffer failed: %lu\n", GetLastError());
        goto finish;
    }

    if (!filter_ioctl(filter_handle, IOCTL_USBPCAP_START_FILTERING,
                       &data->filter, sizeof(data->filter)))
    {
        fprintf(stderr, "Start filtering failed: %lu\n", GetLastError());
        goto finish;
    }

    return filter_handle;

finish:
    if (filter_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(filter_handle);
    }

    return INVALID_HANDLE_VALUE;
}

static BOOL write_data(struct thread_data* data, LPOVERLAPPED write_overlapped,
                       void *buffer, DWORD bytes)
{
    DWORD written = 0;
    DWORD err;
    DWORD dw;
    BOOL active = FALSE;
    BOOL success;
    HANDLE table[2] = {data->exit_event, write_overlapped->hEvent};
    if (!capture_running(data))
    {
        return FALSE;
    }
    if (bytes == 0)
    {
        return TRUE;
    }
    /* Write data to the end of the file. */
    write_overlapped->Offset = 0xFFFFFFFF;
    write_overlapped->OffsetHigh = 0xFFFFFFFF;
    if (!ResetEvent(write_overlapped->hEvent))
    {
        request_capture_stop(data);
        return FALSE;
    }
    /* A byte-count pointer is needed for borrowed synchronous stdout too. */
    success = WriteFile(data->write_handle, buffer, bytes, &written, write_overlapped);
    err = success ? ERROR_SUCCESS : GetLastError();
    if (success && data->write_handle_owned)
    {
        /* On an asynchronous handle the WriteFile byte-count out parameter
         * is not authoritative, even for immediate completion. */
        active = TRUE;
        success = complete_io(data->write_handle, write_overlapped, &written, &active, FALSE);
        err = success ? ERROR_SUCCESS : GetLastError();
        if (!success)
        {
            request_capture_stop(data);
            drain_io(data->write_handle, write_overlapped, &active);
        }
    }
    else if (!success && (err == ERROR_IO_PENDING))
    {
        active = TRUE;
        dw = WaitForMultipleObjects(2, table, FALSE, INFINITE);
        if ((dw == WAIT_OBJECT_0 + 1) && capture_running(data))
        {
            success = complete_io(data->write_handle, write_overlapped, &written, &active, FALSE);
            err = success ? ERROR_SUCCESS : GetLastError();
        }
        else
        {
            err = (dw == WAIT_FAILED) ? GetLastError() : ERROR_OPERATION_ABORTED;
        }
        if (!success)
        {
            request_capture_stop(data);
        }
        /* Also drain if completion retrieval itself failed while still pending. */
        drain_io(data->write_handle, write_overlapped, &active);
    }
    if (!success)
    {
        fprintf(stderr, "Write failed (%lu). Stopping capture.\n", err);
        request_capture_stop(data);
        return FALSE;
    }
    if (written != bytes)
    {
        fprintf(stderr, "Wrote %lu bytes instead of %lu. Stopping capture.\n", written, bytes);
        request_capture_stop(data);
        return FALSE;
    }
    if (capture_running(data))
    {
        /* Preserve existing successful-write flush behavior. */
        FlushFileBuffers(data->write_handle);
    }
    return capture_running(data);
}

static void process_data(struct thread_data* data, LPOVERLAPPED write_overlapped,
                         unsigned char *buffer, DWORD bytes)
{
    if (data->descriptors.buf_written < sizeof(pcap_hdr_t))
    {
        DWORD to_write = sizeof(pcap_hdr_t) - data->descriptors.buf_written;
        if (to_write > bytes)
        {
            to_write = bytes;
        }
        memcpy(&data->descriptors.buf[data->descriptors.buf_written], buffer, to_write);
        data->descriptors.buf_written += to_write;

        if (data->descriptors.buf_written == sizeof(pcap_hdr_t))
        {
            pcap_hdr_t *hdr = (pcap_hdr_t *)data->descriptors.buf;
            if (!write_data(data, write_overlapped, data->descriptors.buf, sizeof(pcap_hdr_t)))
            {
                return;
            }
            if ((hdr->magic_number == 0xA1B2C3D4) && (hdr->network == DLT_USBPCAP) && (data->descriptors.descriptors_len > 0))
            {
                if (!write_data(data, write_overlapped, data->descriptors.descriptors, data->descriptors.descriptors_len))
                {
                    return;
                }
            }
        }
        buffer += to_write;
        bytes -= to_write;

        if (bytes == 0)
        {
            /* Nothing more to write */
            return;
        }
    }
    write_data(data, write_overlapped, buffer, bytes);
}

/* Called only by the worker, after the preceding request has completed. */
static BOOL start_read(HANDLE handle, void *buffer, DWORD length,
                       LPOVERLAPPED overlapped, BOOL *active)
{
    DWORD bytes = 0;
    BOOL success;
    DWORD err;
    if (!ResetEvent(overlapped->hEvent))
    {
        return FALSE;
    }
    success = ReadFile(handle, buffer, length, &bytes, overlapped);
    err = success ? ERROR_SUCCESS : GetLastError();
    *active = success || (err == ERROR_IO_PENDING);
    if (success)
    {
        /* Includes immediate completion; never wait on an unissued request. */
        return SetEvent(overlapped->hEvent);
    }
    SetLastError(err);
    return *active;
}

DWORD WINAPI read_thread(LPVOID param)
{
    struct thread_data* data = (struct thread_data*)param;
    unsigned char* buffer = NULL;
    unsigned char dummy_buf = 0;
    OVERLAPPED read_overlapped = {0};
    OVERLAPPED write_overlapped = {0};
    OVERLAPPED connect_overlapped = {0};
    OVERLAPPED monitor_overlapped = {0};
    BOOL read_active = FALSE;
    BOOL connect_active = FALSE;
    BOOL monitor_active = FALSE;
    DWORD read = 0;
    DWORD err;
    HANDLE table[4];
    DWORD table_count;
    DWORD dw;
    HANDLE signaled;

    if ((data->read_handle == NULL) || (data->read_handle == INVALID_HANDLE_VALUE) ||
        (data->write_handle == NULL) || (data->write_handle == INVALID_HANDLE_VALUE) ||
        (data->exit_event == NULL) || (data->exit_event == INVALID_HANDLE_VALUE))
    {
        fprintf(stderr, "Thread started with invalid capture handle!\n");
        goto finish;
    }
    if (!capture_running(data))
    {
        goto finish;
    }
    buffer = malloc(data->bufferlen);
    if (buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate user-mode buffer (length %u)\n", data->bufferlen);
        goto finish;
    }
    read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    connect_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    monitor_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if ((read_overlapped.hEvent == NULL) || (connect_overlapped.hEvent == NULL) ||
        (write_overlapped.hEvent == NULL) || (monitor_overlapped.hEvent == NULL))
    {
        fprintf(stderr, "Failed to create capture I/O events: %lu\n", GetLastError());
        goto finish;
    }
    /* Never issue a potentially synchronous/read-forbidden read on borrowed
     * stdout. Only owned overlapped duplex pipes support the disconnect probe. */
    if (data->monitor_write_handle && capture_running(data))
    {
        if (!start_read(data->write_handle, &dummy_buf, sizeof(dummy_buf),
                         &monitor_overlapped, &monitor_active))
        {
            fprintf(stderr, "Pipe monitor read failed: %lu\n", GetLastError());
            goto finish;
        }
    }
    if (!capture_running(data))
    {
        goto finish;
    }
    if (GetFileType(data->read_handle) == FILE_TYPE_PIPE)
    {
        BOOL success = ConnectNamedPipe(data->read_handle, &connect_overlapped);
        err = success ? ERROR_SUCCESS : GetLastError();
        connect_active = success || (err == ERROR_IO_PENDING);
        if (success)
        {
            if (!SetEvent(connect_overlapped.hEvent))
            {
                goto finish;
            }
        }
        else if (err == ERROR_PIPE_CONNECTED)
        {
            /* The client won the connect race. No connect request is pending
             * and Windows need not signal the supplied event in this case. */
            if (capture_running(data) && !start_read(data->read_handle, buffer,
                    data->bufferlen, &read_overlapped, &read_active))
            {
                fprintf(stderr, "ReadFile failed: %lu\n", GetLastError());
                goto finish;
            }
        }
        else if (!connect_active)
        {
            fprintf(stderr, "ConnectNamedPipe failed: %lu\n", err);
            goto finish;
        }
    }
    else if (!start_read(data->read_handle, buffer, data->bufferlen,
                          &read_overlapped, &read_active))
    {
        fprintf(stderr, "ReadFile failed: %lu\n", GetLastError());
        goto finish;
    }

    while (capture_running(data))
    {
        /* Put stop first so a continuously ready read cannot starve shutdown. */
        table_count = 0;
        table[table_count++] = data->exit_event;
        if (read_active) table[table_count++] = read_overlapped.hEvent;
        if (connect_active) table[table_count++] = connect_overlapped.hEvent;
        if (monitor_active) table[table_count++] = monitor_overlapped.hEvent;
        dw = WaitForMultipleObjects(table_count, table, FALSE, INFINITE);
        if (dw >= WAIT_OBJECT_0 + table_count)
        {
            fprintf(stderr, "WaitForMultipleObjects failed in read_thread: %lu\n", GetLastError());
            break;
        }
        if (!capture_running(data))
        {
            break;
        }
        signaled = table[dw - WAIT_OBJECT_0];
        if (signaled == read_overlapped.hEvent)
        {
            read = 0;
            if (!complete_io(data->read_handle, &read_overlapped, &read, &read_active, FALSE))
            {
                fprintf(stderr, "Read completion failed: %lu\n", GetLastError());
                break;
            }
            if (read > data->bufferlen)
            {
                fprintf(stderr, "Read completion exceeded capture buffer.\n");
                break;
            }
            process_data(data, &write_overlapped, buffer, read);
            if (capture_running(data) && !start_read(data->read_handle, buffer,
                    data->bufferlen, &read_overlapped, &read_active))
            {
                fprintf(stderr, "ReadFile failed: %lu\n", GetLastError());
                break;
            }
        }
        else if (signaled == connect_overlapped.hEvent)
        {
            if (!complete_io(data->read_handle, &connect_overlapped, &read, &connect_active, FALSE))
            {
                fprintf(stderr, "Pipe connect completion failed: %lu\n", GetLastError());
                break;
            }
            if (capture_running(data) && !start_read(data->read_handle, buffer,
                    data->bufferlen, &read_overlapped, &read_active))
            {
                fprintf(stderr, "ReadFile failed: %lu\n", GetLastError());
                break;
            }
        }
        else if (signaled == monitor_overlapped.hEvent)
        {
            if (!complete_io(data->write_handle, &monitor_overlapped, &read, &monitor_active, FALSE))
            {
                /* Do not consult stale GetLastError after a successful read. */
                fprintf(stderr, "Pipe monitor completion failed: %lu\n", GetLastError());
                break;
            }
            if (capture_running(data) && !start_read(data->write_handle, &dummy_buf,
                    sizeof(dummy_buf), &monitor_overlapped, &monitor_active))
            {
                fprintf(stderr, "Pipe monitor read failed: %lu\n", GetLastError());
                break;
            }
        }
    }

finish:
    /* Signal stop early; only the thread handle (join) proves rundown is done.
     * No buffers, stack OVERLAPPEDs, events or shared handles retire beforehand. */
    request_capture_stop(data);
    drain_io(data->read_handle, &read_overlapped, &read_active);
    drain_io(data->read_handle, &connect_overlapped, &connect_active);
    drain_io(data->write_handle, &monitor_overlapped, &monitor_active);
    if (read_overlapped.hEvent != NULL) CloseHandle(read_overlapped.hEvent);
    if (connect_overlapped.hEvent != NULL) CloseHandle(connect_overlapped.hEvent);
    if (write_overlapped.hEvent != NULL) CloseHandle(write_overlapped.hEvent);
    if (monitor_overlapped.hEvent != NULL) CloseHandle(monitor_overlapped.hEvent);
    free(buffer);
    return 0;
}
