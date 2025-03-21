/*
 * sftp_aio.c - Secure FTP functions for asynchronous i/o
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
 * Copyright (c) 2008-2018 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2023 by Eshan Kelkar <eshankelkar@galorithm.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <errno.h>

#include "libssh/sftp.h"
#include "libssh/sftp_priv.h"
#include "libssh/buffer.h"
#include "libssh/session.h"

#ifdef WITH_SFTP

struct sftp_aio_struct {
    sftp_file file;
    uint32_t id;
    size_t len;
};

static sftp_aio sftp_aio_new(void)
{
    sftp_aio aio = NULL;
    aio = calloc(1, sizeof(struct sftp_aio_struct));
    return aio;
}

void sftp_aio_free(sftp_aio aio)
{
    SAFE_FREE(aio);
}

ssize_t sftp_aio_begin_read(sftp_file file, size_t len, sftp_aio *aio)
{
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    sftp_aio aio_handle = NULL;
    uint32_t id, read_len;
    int rc;

    if (file == NULL ||
        file->sftp == NULL ||
        file->sftp->session == NULL) {
        return SSH_ERROR;
    }

    sftp = file->sftp;
    if (len == 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, 0 passed as the number of "
                      "bytes to read");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /* Apply a cap on the length a user is allowed to read
     *
     * The limits are in theory uint64, but packet contain data length in uint32
     * so in practice, the limit will never be larger than UINT32_MAX
     */
    read_len = (uint32_t)MIN(sftp->limits->max_read_length, len);

    if (aio == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed instead of a pointer to "
                      "a location to store an sftp aio handle");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);

    rc = ssh_buffer_pack(buffer,
                         "dSqd",
                         id,
                         file->handle,
                         file->offset,
                         read_len);

    if (rc != SSH_OK) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    aio_handle = sftp_aio_new();
    if (aio_handle == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    aio_handle->file = file;
    aio_handle->id = id;
    aio_handle->len = read_len;

    rc = sftp_packet_write(sftp, SSH_FXP_READ, buffer);
    SSH_BUFFER_FREE(buffer);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(aio_handle);
        return SSH_ERROR;
    }

    /* Assume we read len bytes from the file */
    file->offset += read_len;
    *aio = aio_handle;
    return read_len;
}

ssize_t sftp_aio_wait_read(sftp_aio *aio,
                           void *buf,
                           size_t buf_size)
{
    sftp_file file = NULL;
    size_t bytes_requested;
    sftp_session sftp = NULL;
    sftp_message msg = NULL;
    sftp_status_message status = NULL;
    uint32_t string_len, host_len;
    int rc, err;

    /*
     * This function releases the memory of the structure
     * that (*aio) points to in all cases except when the
     * return value is SSH_AGAIN.
     *
     * If the return value is SSH_AGAIN, the user should call this
     * function again to get the response for the request corresponding
     * to the structure that (*aio) points to, hence we don't release the
     * structure's memory when SSH_AGAIN is returned.
     */

    if (aio == NULL || *aio == NULL) {
        return SSH_ERROR;
    }

    file = (*aio)->file;
    bytes_requested = (*aio)->len;

    if (file == NULL ||
        file->sftp == NULL ||
        file->sftp->session == NULL) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    sftp = file->sftp;
    if (bytes_requested == 0) {
        /* should never happen */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp aio, len for requested i/o is 0");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (buf == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed "
                      "instead of a buffer's address");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (buf_size < bytes_requested) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Buffer size (%zu, passed by the caller) is "
                      "smaller than the number of bytes requested "
                      "to read (%zu, as per the supplied sftp aio)",
                      buf_size, bytes_requested);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /* handle an existing request */
    rc = sftp_recv_response_msg(sftp, (*aio)->id, !file->nonblocking, &msg);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (rc == SSH_AGAIN) {
        /* return without freeing the (*aio) */
        return SSH_AGAIN;
    }

    /*
     * Release memory for the structure that (*aio) points to
     * as all further points of return are for success or
     * failure.
     */
    SFTP_AIO_FREE(*aio);

    switch (msg->packet_type) {
    case SSH_FXP_STATUS:
        status = parse_status_msg(msg);
        sftp_message_free(msg);
        if (status == NULL) {
            return SSH_ERROR;
        }

        sftp_set_error(sftp, status->status);
        if (status->status != SSH_FX_EOF) {
            ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
                          "SFTP server : %s", status->errormsg);
            err = SSH_ERROR;
        } else {
            file->eof = 1;
            /* Update the offset correctly */
            file->offset = file->offset - bytes_requested;
            err = SSH_OK;
        }

        status_msg_free(status);
        return err;

    case SSH_FXP_DATA:
        rc = ssh_buffer_get_u32(msg->payload, &string_len);
        if (rc == 0) {
            /* Insufficient data in the buffer */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Received invalid DATA packet from sftp server");
            sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        host_len = ntohl(string_len);
        if (host_len > buf_size) {
            /*
             * This should never happen, as according to the
             * SFTP protocol the server reads bytes less than
             * or equal to the number of bytes requested to read.
             *
             * And we have checked before that the buffer size is
             * greater than or equal to the number of bytes requested
             * to read, hence code of this if block should never
             * get executed.
             */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "DATA packet (%u bytes) received from sftp server "
                          "cannot fit into the supplied buffer (%zu bytes)",
                          host_len, buf_size);
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        string_len = ssh_buffer_get_data(msg->payload, buf, host_len);
        if (string_len != host_len) {
            /* should never happen */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Received invalid DATA packet from sftp server");
            sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        /* Update the offset with the correct value */
        file->offset = file->offset - (bytes_requested - string_len);
        sftp_message_free(msg);
        return string_len;

    default:
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Received message %d during read!", msg->packet_type);
        sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
        sftp_message_free(msg);
        return SSH_ERROR;
    }

    return SSH_ERROR; /* not reached */
}

ssize_t sftp_aio_begin_write(sftp_file file,
                             const void *buf,
                             size_t len,
                             sftp_aio *aio)
{
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    sftp_aio aio_handle = NULL;
    uint32_t id, write_len;
    int rc;

    if (file == NULL ||
        file->sftp == NULL ||
        file->sftp->session == NULL) {
        return SSH_ERROR;
    }

    sftp = file->sftp;
    if (buf == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed instead "
                      "of a buffer's address");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (len == 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, 0 passed as the number "
                      "of bytes to write");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /* Apply a cap on the length a user is allowed to write
     *
     * The limits are in theory uint64, but packet contain data length in uint32
     * so in practice, the limit will never be larger than UINT32_MAX
     */
    write_len = (uint32_t)MIN(sftp->limits->max_write_length, len);

    if (aio == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed instead of a pointer to "
                      "a location to store an sftp aio handle");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);
    rc = ssh_buffer_pack(buffer,
                         "dSqdP",
                         id,
                         file->handle,
                         file->offset,
                         write_len, /* len of datastring */
                         (size_t)write_len,
                         buf);

    if (rc != SSH_OK) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    aio_handle = sftp_aio_new();
    if (aio_handle == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    aio_handle->file = file;
    aio_handle->id = id;
    aio_handle->len = write_len;

    rc = sftp_packet_write(sftp, SSH_FXP_WRITE, buffer);
    SSH_BUFFER_FREE(buffer);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(aio_handle);
        return SSH_ERROR;
    }

    /* Assume we wrote len bytes to the file */
    file->offset += write_len;
    *aio = aio_handle;
    return write_len;
}

ssize_t sftp_aio_wait_write(sftp_aio *aio)
{
    sftp_file file = NULL;
    size_t bytes_requested;

    sftp_session sftp = NULL;
    sftp_message msg = NULL;
    sftp_status_message status = NULL;
    int rc;

    /*
     * This function releases the memory of the structure
     * that (*aio) points to in all cases except when the
     * return value is SSH_AGAIN.
     *
     * If the return value is SSH_AGAIN, the user should call this
     * function again to get the response for the request corresponding
     * to the structure that (*aio) points to, hence we don't release the
     * structure's memory when SSH_AGAIN is returned.
     */

    if (aio == NULL || *aio == NULL) {
        return SSH_ERROR;
    }

    file = (*aio)->file;
    bytes_requested = (*aio)->len;

    if (file == NULL ||
        file->sftp == NULL ||
        file->sftp->session == NULL) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    sftp = file->sftp;
    if (bytes_requested == 0) {
        /* This should never happen */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp aio, len for requested i/o is 0");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    rc = sftp_recv_response_msg(sftp, (*aio)->id, !file->nonblocking, &msg);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (rc == SSH_AGAIN) {
        /* Return without freeing the (*aio) */
        return SSH_AGAIN;
    }

    /*
     * Release memory for the structure that (*aio) points to
     * as all further points of return are for success or
     * failure.
     */
    SFTP_AIO_FREE(*aio);

    if (msg->packet_type == SSH_FXP_STATUS) {
        status = parse_status_msg(msg);
        sftp_message_free(msg);
        if (status == NULL) {
            return SSH_ERROR;
        }

        sftp_set_error(sftp, status->status);
        if (status->status == SSH_FX_OK) {
            status_msg_free(status);
            return bytes_requested;
        }

        ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
                      "SFTP server: %s", status->errormsg);
        status_msg_free(status);
        return SSH_ERROR;
    }

    ssh_set_error(sftp->session, SSH_FATAL,
                  "Received message %d during write!",
                  msg->packet_type);
    sftp_message_free(msg);
    sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
    return SSH_ERROR;
}

/**
 * @internal
 *
 * @brief Begin a data chunk transfer from a local file to a remote file.
 *
 * This function caps the length which the caller requests to read from a local
 * file and write to the remote file. The value of the cap is same as the value
 * of the max_write_length field of the sftp_limits returned by sftp_limits().
 *
 * Then it tries to read the requested number of bytes (after capping) from
 * the local file. After reading, it sends a write request for the read data
 * to the sftp server, allocates memory to store information about the sent
 * request and provides the caller an sftp aio handle to that memory.
 *
 * In case EOF is encountered before reading a single byte from the
 * local file, no write request is sent and NULL is provided to the
 * caller instead of a sftp aio handle. This scenario is not considered
 * as an error and SSH_OK is returned with the count of number of bytes
 * read (which the caller can check through the value result argument)
 * set to 0.
 *
 * @param[in]     remote_file        sftp file handle of the remote file to
 *                                   write to.
 *
 * @param[in]     local_fd           File descriptor of the local file to read
 *                                   from.
 *
 * @param[in,out] value_res_ptr
 * @parblock
 *                                   A value-result pointer.
 *
 *                                   Value of the pointed variable set by
 *                                   the caller before the call specifies the
 *                                   number of bytes to read from the local
 *                                   file.
 *
 *                                   On success, this function sets the value of
 *                                   the pointed variable to the number of bytes
 *                                   read from the local file.
 *
 *                                   On error, the value of the pointed variable
 *                                   is left untouched.
 * @endparblock
 * @param[out]   aio                 Pointer to the location to store the
 *                                   sftp aio handle corresponding to sent
 *                                   request. In case EOF is encountered before
 *                                   reading a single byte, NULL is stored at
 *                                   that location.
 *
 * @returns                          SSH_OK on success, SSH_ERROR on error.
 */
int aio_begin_l2r(sftp_file remote_file,
                  int local_fd,
                  size_t *value_res_ptr,
                  sftp_aio *aio)
{
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    uint32_t *count_ptr = NULL;
    uint8_t *data_ptr = NULL;

    char errno_msg[SSH_ERRNO_MSG_MAX] = {0};
    size_t to_read;
    ssize_t bytes_read;
    uint32_t id, to_cut, bytes_cut;
    int rc;

    if (remote_file == NULL ||
        remote_file->sftp == NULL ||
        remote_file->sftp->session == NULL) {
        return SSH_ERROR;
    }

    sftp = remote_file->sftp;
    if (local_fd < 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid local file descriptor %d passed as an argument",
                      local_fd);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (value_res_ptr == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed as the value-result "
                      "argument");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (*value_res_ptr == 0) {
         ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid value-result argument, specifies 0 as the "
                      "number of bytes to read from the local file");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (aio == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid argument, NULL passed instead of a pointer to "
                      "a location to store an sftp aio handle");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /*
     * Cap the number of bytes to read from the local file as per the max
     * number of bytes which can be sent in an sftp write request.
     */
    to_read = MIN(*value_res_ptr, sftp->limits->max_write_length);

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);
    rc = ssh_buffer_pack(buffer,
                         "dSq",
                         id,
                         remote_file->handle,
                         remote_file->offset);

    if (rc != SSH_OK) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    /*
     * Allocate memory at the tail of the ssh buffer for :
     * - A uint32_t to store the count of the bytes read from the local file.
     * - Memory to store the bytes to read from the local file.
     *
     * NOTE: The below code avoids using two separate ssh_buffer_allocate()
     * calls for this allocation.
     *
     * This is because ssh_buffer_allocate() uses realloc() internally to expand
     * the ssh buffer, and realloc'ing the ssh buffer due to the second
     * ssh_buffer_allocate() call may deallocate the memory at the address
     * returned by the first ssh_buffer_allocate() call.
     *
     * Hence this realloc'ing is dangerous if the address returned by the first
     * ssh_buffer_allocate() call needs to be used after the second
     * ssh_buffer_allocate() call, which would've been the case had we used two
     * ssh_buffer_allocate() calls below.
     */
    count_ptr = ssh_buffer_allocate(buffer, sizeof(uint32_t) + to_read);
    if (count_ptr == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    /*
     * Due to pointer arithmetic, data_ptr will store the address of the byte
     * after the uint32_t that count_ptr points to.
     */
    data_ptr = (uint8_t *)(count_ptr + 1);

    /*
     * Read data directly from the local file into the ssh buffer prepared for
     * the write request.
     */
    bytes_read = ssh_readn(local_fd, data_ptr, to_read);
    if (bytes_read == -1) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Failed to read data from the local file to "
                      "the libssh buffer, reason : %s",
                      ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    if (bytes_read == 0) {
        /*
         * EOF encountered on the local file before reading a single byte,
         * hence no data was read from the local file and hence no write
         * request for the remote file is being sent in this case.
         */
        SSH_BUFFER_FREE(buffer);
        *value_res_ptr = 0;
        *aio = NULL;
        return SSH_OK;
    }

    *count_ptr = htonl(bytes_read);

    /*
     * Adjust the ssh buffer's length according to the actual number of bytes
     * read.
     */
    if ((size_t)bytes_read != to_read) {
        to_cut = to_read - bytes_read;
        bytes_cut = ssh_buffer_pass_bytes_end(buffer, to_cut);
        if (bytes_cut != to_cut) {
            /*
             * Should not happen as the ssh buffer's length is certainly greater
             * than the value of to_cut.
             */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Failed to adjust the ssh buffer");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            SSH_BUFFER_FREE(buffer);
            return SSH_ERROR;
        }
    }

    *aio = sftp_aio_new();
    if (*aio == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    (*aio)->file = remote_file;
    (*aio)->id = id;
    (*aio)->len = bytes_read;

    rc = sftp_packet_write(sftp, SSH_FXP_WRITE, buffer);
    SSH_BUFFER_FREE(buffer);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /*
     * Assume that the bytes read from the local file have been written into
     * the remote file.
     */
    remote_file->offset += bytes_read;

    *value_res_ptr = bytes_read;
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Wait for an async remote read to complete and write
 * the read data in a local file.
 *
 * This function tries to write the bytes read from the remote
 * file to the local file until those many bytes are written or
 * some failure occurs.
 *
 * A pointer to a sftp aio handle should be passed while calling
 * this function. Except when the return value is SSH_AGAIN,
 * this function releases the memory corresponding to the supplied
 * aio handle and assigns NULL to that aio handle using the passed
 * pointer to that handle.
 *
 * If the remote file is opened in non-blocking mode and the request
 * hasn't been executed yet this function returns SSH_AGAIN and must
 * be called again using the same sftp aio handle.
 *
 * @param[in] aio                  Pointer to the sftp aio handle returned by
 *                                 sftp_aio_begin_read().
 *
 * @param[in] fd                   The file descriptor of the local file
 *                                 in which data read from the remote file
 *                                 will be written.
 *
 * @returns                        Number of bytes read from the remote file
 *                                 and written to the local file on success,
 *                                 SSH_ERROR on error.
 *
 * @warning                        A call to this function with an invalid
 *                                 sftp aio handle may never return.
 *
 * @see sftp_aio_begin_read()
 */
ssize_t aio_wait_r2l(sftp_aio *aio, int local_fd)
{
    sftp_file remote_file = NULL;
    size_t bytes_requested;

    sftp_session sftp = NULL;
    sftp_message msg = NULL;
    sftp_status_message status = NULL;

    char errno_msg[SSH_ERRNO_MSG_MAX] = {0};
    uint32_t string_len, host_len;
    int32_t bytes_written;
    int rc, err;

    if (aio == NULL || *aio == NULL) {
        return SSH_ERROR;
    }

    remote_file = (*aio)->file;
    bytes_requested = (*aio)->len;

    if (remote_file == NULL ||
        remote_file->sftp == NULL ||
        remote_file->sftp->session == NULL) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    sftp = remote_file->sftp;
    if (bytes_requested == 0) {
        /* should never happen */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp aio, len for requested i/o is 0");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (local_fd < 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid local file descriptor %d passed as an "
                      "argument", local_fd);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /* handle an existing request */
    rc = sftp_recv_response_msg(sftp, (*aio)->id, !remote_file->nonblocking, &msg);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    if (rc == SSH_AGAIN) {
        return SSH_AGAIN;
    }

    /*
     * Release memory of the structure that (*aio) points to
     * as all further points of return are for success or
     * failure.
     */
    SFTP_AIO_FREE(*aio);

    switch (msg->packet_type) {
    case SSH_FXP_STATUS:
        status = parse_status_msg(msg);
        sftp_message_free(msg);
        if (status == NULL) {
            return SSH_ERROR;
        }

        sftp_set_error(sftp, status->status);
        if (status->status != SSH_FX_EOF) {
            ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
                          "SFTP server : %s", status->errormsg);
            err = SSH_ERROR;
        } else {
            remote_file->eof = 1;
            /* Update the offset correctly */
            remote_file->offset -= bytes_requested;
            err = SSH_OK;
        }

        status_msg_free(status);
        return err;

    case SSH_FXP_DATA:
        rc = ssh_buffer_get_u32(msg->payload, &string_len);
        if (rc == 0) {
            /* Insufficient data in the buffer */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Received invalid DATA packet from sftp server");
            sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        host_len = ntohl(string_len);

        /*
         * Check whether the ssh buffer contains at least
         * host_len bytes or not.
         */
        rc = ssh_buffer_validate_length(msg->payload, host_len);
        if (rc == SSH_ERROR) {
           ssh_set_error(sftp->session, SSH_FATAL,
                         "Received invalid DATA packet from sftp server");
            sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        bytes_written = ssh_buffer_file_write(msg->payload,
                                              local_fd,
                                              host_len);
        if (bytes_written == SSH_ERROR) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Failed to write to the local file, "
                          "reason : %s",
                          ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        if ((uint32_t)bytes_written != host_len) {
            /*
             * Should never happen if ssh_buffer_file_write() is
             * successful, as it tries to write the requested number
             * of bytes until those many bytes are written (or) some
             * failure occurs.
             */
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Short write on local file, requested to write "
                          "%"PRIu32" bytes, wrote only %d bytes",
                          host_len, bytes_written);
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_message_free(msg);
            return SSH_ERROR;
        }

        /* Update the offset correctly */
        remote_file->offset -= (bytes_requested - host_len);
        sftp_message_free(msg);
        return host_len;

    default:
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Received message %d during read!", msg->packet_type);
        sftp_set_error(sftp, SSH_FX_BAD_MESSAGE);
        sftp_message_free(msg);
        return SSH_ERROR;
    }

    return SSH_ERROR; /* not reached */
}

/**
 * @internal
 *
 * @brief Wait for an async remote read to complete and begin an async remote
 * write for the read data.
 *
 * If the remote file for reading is opened in non-blocking mode and the read
 * request hasn't been executed yet, this function returns SSH_AGAIN and must
 * be called again using the same sftp aio handle.
 *
 * @param[in,out] aio
 * @parblock
 *                                 A value result pointer.
 *
 *                                 An sftp aio handle returned by
 *                                 sftp_aio_begin_read() should be stored at
 *                                 the pointed location by the caller. This
 *                                 handle specifies information about the async
 *                                 read request to wait for.
 *
 *                                 If the return value is SSH_AGAIN, the
 *                                 supplied sftp aio handle present at the
 *                                 pointed location is left untouched.
 *
 *                                 Except when the return value is SSH_AGAIN,
 *                                 the memory corresponding to the supplied
 *                                 sftp aio handle present at the pointed
 *                                 location is released.
 *
 *                                 On success, if the async read response
 *                                 contains at least one byte of data, an async
 *                                 write request is sent for that data and the
 *                                 sftp aio handle corresponding to the sent
 *                                 request is stored at the pointed location.
 *
 *                                 On success, if the async read response
 *                                 contains EOF, no async write request is sent
 *                                 since there is no data to write and NULL is
 *                                 stored at the pointed location.
 *
 *                                 On error, NULL is stored at the pointed
 *                                 location.
 * @endparblock
 * @param[in] file_out             The open sftp file handle to write to.
 *
 * @returns                        On success, the number of bytes read in the
 *                                 async remote read and requested to write in
 *                                 the async remote write are returned.
 *
 * @retval 0                       On success, If 0 bytes were read before
 *                                 encountering EOF in the async remote read.
 *                                 No async write request is sent in this case.
 *
 * @retval SSH_AGAIN               If remote file for reading corresponding to
 *                                 the supplied sftp aio handle is opened in
 *                                 non-blocking mode and the read request hasn't
 *                                 been executed yet.
 *
 * @retval SSH_ERROR               On error.
 *
 * @warning                        A call to this function with an invalid
 *                                 sftp aio handle may never return.
 *
 * @see sftp_aio_begin_read()
 */
ssize_t aio_wait_begin_r2r(sftp_aio *aio, sftp_file file_out)
{
    sftp_session sftp = NULL;
    ssh_buffer buffer = NULL;
    uint32_t *count_ptr = NULL;
    void *data_ptr = NULL;

    uint32_t id, to_cut, bytes_cut;
    size_t bytes_requested;
    ssize_t bytes_read;
    int rc;

    if (aio == NULL || *aio == NULL ||
        file_out == NULL ||
        file_out->sftp == NULL ||
        file_out->sftp->session == NULL) {

        if (aio != NULL && *aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }
        return SSH_ERROR;
    }

    sftp = file_out->sftp;
    bytes_requested = (*aio)->len;

    id = sftp_get_new_id(sftp);

    /*
     * Prepare an ssh buffer for a remote write request for writing to
     * file_out.
     */
    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(buffer,
                         "dSq",
                         id,
                         file_out->handle,
                         file_out->offset);
    if (rc == SSH_ERROR) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /*
     * Allocate memory at the tail of the ssh buffer for :
     * - A uint32_t to store the count of the bytes to write to file_out
     * - Memory to store the bytes to write to file_out.
     *
     * NOTE: The below code avoids using two separate ssh_buffer_allocate()
     * calls for this allocation.
     *
     * This is because ssh_buffer_allocate() uses realloc() internally to expand
     * the ssh buffer, and realloc'ing the ssh buffer due to the second
     * ssh_buffer_allocate() call may deallocate the memory at the address
     * returned by the first ssh_buffer_allocate() call.
     *
     * Hence this realloc'ing is dangerous if the address returned by the first
     * ssh_buffer_allocate() call needs to be used after the second
     * ssh_buffer_allocate() call, which would've been the case had we used two
     * ssh_buffer_allocate() calls below.
     */
    count_ptr = ssh_buffer_allocate(buffer, sizeof(uint32_t) + bytes_requested);
    if (count_ptr == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /*
     * Due to pointer arithmetic, data_ptr will store the address of the byte
     * after the uint32_t that count_ptr points to.
     */
    data_ptr = count_ptr + 1;

    /*
     * Wait for the remote read corresponding to aio to complete and store the
     * read data directly in the ssh buffer prepared for a write request for
     * writing to file_out.
     */
    bytes_read = sftp_aio_wait_read(aio, data_ptr, bytes_requested);

    /*
     * Memory corresponding to (*aio) will be freed by sftp_aio_wait_read()
     * except when it returns SSH_AGAIN.
     */

    if (bytes_read == SSH_ERROR) {
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    if (bytes_read == SSH_AGAIN) {
        SSH_BUFFER_FREE(buffer);
        return SSH_AGAIN;
    }

    /*
     * bytes_read > 0 is a defensive check that ensures that the second
     * condition is evaluated only when bytes_read is +ve.
     *
     * This is kept so that if the code is reformatted in future (e.g the
     * following "if" is moved above the "if" for SSH_ERROR and "if" for
     * SSH_AGAIN), then the second condition should NOT get evaluated for
     * bytes_read == SSH_ERROR(-1) and bytes_read == SSH_AGAIN(-2).
     *
     * Because that 2nd condition if evaluated, would probably evaluate to true
     * for those negatives (as the code casts bytes_read to uint64_t before
     * comparing) but we don't want the following ("if")'s code to get executed
     * for those negative values.
     */
    if (bytes_read > 0 &&
        (uint64_t)bytes_read > sftp->limits->max_write_length) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Cannot send the read bytes in a single remote write "
                      "request as the number of bytes read (%zd) exceed "
                      "libssh's sftp limit for writing (%"PRIu64")",
                       bytes_requested, sftp->limits->max_write_length);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    if (bytes_read == 0) {
        SSH_BUFFER_FREE(buffer);
        return 0;
    }

    *count_ptr = htonl(bytes_read);

    /*
     * The ssh buffer was allocated according to the number of bytes requested
     * to read. After reading into the ssh buffer, update its length according
     * to the number of bytes actually read.
     */
    to_cut = bytes_requested - bytes_read;
    if (to_cut > 0) {
        bytes_cut = ssh_buffer_pass_bytes_end(buffer, to_cut);
        if (bytes_cut != to_cut) {
            /*
             * Should not happen since the ssh buffer's length is surely greater
             * than the value of to_cut.
             */
            SSH_BUFFER_FREE(buffer);
            return SSH_ERROR;
        }
    }

    *aio = sftp_aio_new();
    if (*aio == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SSH_BUFFER_FREE(buffer);
        return SSH_ERROR;
    }

    (*aio)->file = file_out;
    (*aio)->id = id;
    (*aio)->len = (size_t)bytes_read;

    rc = sftp_packet_write(sftp, SSH_FXP_WRITE, buffer);
    SSH_BUFFER_FREE(buffer);
    if (rc == SSH_ERROR) {
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /* Assume that the data has been written to file_out */
    file_out->offset += bytes_read;

    return bytes_read;
}

#endif /* WITH_SFTP */
