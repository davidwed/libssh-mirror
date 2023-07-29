/*
 * sftp_ft.c - Secure FTP functions for file transfer
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
 * Copyright (c) 2008-2018 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2023-2025 by Eshan Kelkar <eshankelkar@galorithm.com>
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
#include <sys/stat.h>
#include <fcntl.h>

#include "libssh/sftp.h"
#include "libssh/sftp_priv.h"
#include "libssh/buffer.h"
#include "libssh/session.h"

#ifdef WITH_SFTP

struct sftp_ft_struct {
    enum sftp_ft_type_e type;
    mode_t target_mode;
    uint8_t resume_transfer_flag;

    sftp_session sftp;

    char *source_path;
    char *target_path;

    size_t chunk_size;
    size_t in_flight_requests;
    size_t internal_chunk_size;

    void *user_data;
    int (*pgrs_callback)(sftp_ft ft);

    uint64_t bytes_total;
    uint64_t bytes_transferred;

    /*
     * To store the number of bytes that were skipped from the start of the
     * source file before starting a transfer. This metric could be useful for
     * the user when a partial transfer is resumed.
     */
    uint64_t bytes_skipped;

    uint64_t bytes_requested;
};

/**
 * @internal
 *
 * @brief Validate an sftp file transfer structure.
 *
 * @param[in] ft          sftp ft handle to the file transfer structure
 *                        to validate.
 *
 * @return                SSH_OK for a valid file transfer structure,
 *                        SSH_ERROR for an invalid file transfer structure
 */
static int ft_validate(sftp_ft ft) __attr_unused__;
static int ft_validate(sftp_ft ft)
{
    sftp_session sftp = NULL;

    if (ft == NULL ||
        ft->sftp == NULL ||
        ft->sftp->session == NULL) {
        return SSH_ERROR;
    }

    sftp = ft->sftp;

    if (ft->type == SFTP_FT_TYPE_NONE) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, no transfer type set");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->type > SFTP_FT_TYPE_NONE) {
        /*
         * Should never happen, as sftp_ft_new() should set the transfer type to
         * SFTP_FT_TYPE_NONE and sftp_ft_options_set() shouldn't allow the user
         * to set an invalid transfer type, hence the file transfer structure
         * should never contain an invalid transfer type.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, transfer type is invalid");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->source_path == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, source path is NULL");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->target_path == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, target path is NULL");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /*
     * The internal ft_*() functions are responsible for setting and updating
     * the bytes_* fields of a file transfer structure during a transfer. The
     * user can only get the values of those fields.
     *
     * Hence, the failure of any one of the following sanity checks would likely
     * indicate an overflow or a logical error in the code of the ft_*()
     * functions.
     */
    if (ft->bytes_transferred > ft->bytes_total) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, bytes transferred "
                      "greater than bytes total");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->bytes_skipped > ft->bytes_total) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, bytes skipped "
                      "greater than bytes total");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->bytes_requested > ft->bytes_total) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, bytes requested "
                      "greater than bytes total");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    if (ft->bytes_transferred > ft->bytes_requested) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid sftp ft, bytes transferred "
                      "greater than bytes requested");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /* valid sftp ft */
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Set an internal chunk size based on the chunk size and the transfer
 * type specified by the user. This is the chunk size which would
 * actually be used by the API for the transfer.
 *
 * @param[in] ft          sftp ft handle to the file transfer structure.
 *
 * @return                SSH_OK for a valid file transfer structure,
 *                        SSH_ERROR for an invalid file transfer structure
 */
static int ft_set_internal_chunk_size(sftp_ft ft) __attr_unused__;
static int ft_set_internal_chunk_size(sftp_ft ft)
{
    int rc;
    uint64_t cap;
    sftp_session sftp = NULL;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    sftp = ft->sftp;

    /* Get the cap as per the transfer type */
    switch (ft->type) {
    case SFTP_FT_TYPE_UPLOAD:
        /* Cap for uploads */
        cap = sftp->limits->max_write_length;
        break;

    case SFTP_FT_TYPE_DOWNLOAD:
        /* Cap for downloads */
        cap = sftp->limits->max_read_length;
        break;

    case SFTP_FT_TYPE_REMOTE_COPY:
        /*
         * Cap for remote copy = min(max read limit, max write limit)
         *
         * In case of remote copy, when the copy-data extension isn't supported,
         * data chunks have to be downloaded from source and then uploaded to
         * the target. Hence cap for downloading (max read limit) and cap for
         * uploading (max write limit) both get involved in the formula to
         * calculate the cap for remote copy.
         */
        cap = MIN(sftp->limits->max_read_length,
                  sftp->limits->max_write_length);

        break;

    case SFTP_FT_TYPE_LOCAL_COPY:
        ssh_set_error(sftp->session, SSH_FATAL,
                      "The feature to perform a local copy is "
                      "currently not provided by the libssh sftp ft API");
        sftp_set_error(sftp, SSH_FX_OP_UNSUPPORTED);
        return SSH_ERROR;

    case SFTP_FT_TYPE_NONE:
        /*
         * Never reached, as this case is handled by ft_validate()
         * called at the beginning.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "No transfer type specified for the transfer");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;

    default:
        /*
         * Never reached, as this case is handled by ft_validate()
         * called at the beginning.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Invalid transfer type %d", ft->type);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    /* Set the internal chunk size */
    if (ft->chunk_size == 0) {
        /*
         * User wants the API to use the default chunk size for transfer,
         * so use the cap as the default.
         */
        ft->internal_chunk_size = cap;
    } else {
        /*
         * Cap the chunk size specified by the user and use that as the chunk
         * size for the transfer
         */
        ft->internal_chunk_size = MIN(ft->chunk_size, cap);
    }

    return SSH_OK;
}

/*
 * @brief Helper to lseek from the start of a file using an uin64_t offset.
 *
 * This avoids the possible overflow due to an implicit uint64_t -> off_t
 * conversion if an uint64_t is passed directly to lseek().
 *
 * In case the uint64_t type value specified by the caller can't fit into an
 * off_t, this function will return SSH_ERROR with errno set to EOVERFLOW.
 *
 * @param[in] fd          File descriptor to use for seeking.
 *
 * @param[in] off         Offset to seek from start
 *
 * @returns               SSH_OK on success, SSH_ERROR on error with errno set
 *                        to indicate the error.
 */
static int ft_lseek_from_start(int fd, uint64_t offset) __attr_unused__;
static int ft_lseek_from_start(int fd, uint64_t offset)
{
    uint64_t left = offset;
    off_t off, to_seek;

    if (fd < 0) {
        errno = EINVAL;
        return SSH_ERROR;
    }

    /* Set the file offset to 0 initially */
    off = lseek(fd, 0, SEEK_SET);
    if (off == -1) {
        return SSH_ERROR;
    }

    do {
        to_seek = (left > INT32_MAX ? INT32_MAX : left);
        off = lseek(fd, to_seek, SEEK_CUR);
        if (off == -1) {
            return SSH_ERROR;
        }

        left -= (uint64_t)to_seek;
    } while (left > 0);

    return SSH_OK;
}

#ifdef _WIN32

/**
 * @internal
 *
 * @brief Convert Windows style permissions to POSIX style permissions.
 *
 * @param win[in]           Windows style permissions.
 *
 * @param posix_ptr[out]    Pointer to the location to store the POSIX style
 *                          permissions corresponding to the caller supplied
 *                          Windows style permissions.
 *
 * @returns                 SSH_OK on success, SSH_ERROR on error with errno
 *                          set to indicate the error.
 */
static int ft_win_to_posix_perm(mode_t win, mode_t *posix_ptr) __attr_unused__;
static int ft_win_to_posix_perm(mode_t win, mode_t *posix_ptr)
{
    if (posix_ptr == NULL) {
        errno = EINVAL;
        return SSH_ERROR;
    }

    *posix_ptr = 0;
    if ((win & _S_IREAD) == _S_IREAD) {
        /* Enable read permission for user, group and others */
        *posix_ptr |= 0444;
    }

    if ((win & _S_IWRITE) == _S_IWRITE) {
        /* Enable write permission for user, group and others */
        *posix_ptr |= 0222;
    }

    if ((win & _S_IEXEC) == _S_IEXEC) {
        /* Enable execute permission for user, group and others */
        *posix_ptr |= 0111;
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Convert POSIX style permissions to Windows style permissions
 *
 * @param posix[in]         Posix style permissions.
 *
 * @param win_ptr[out]      Pointer to the location to store the Windows style
 *                          permissions corresponding to the caller supplied
 *                          POSIX style permissions.
 *
 * @returns                 SSH_OK on success, SSH_ERROR on error with errno
 *                          set to indicate the error.
 */
static int ft_posix_to_win_perm(mode_t posix, mode_t *win_ptr) __attr_unused__;
static int ft_posix_to_win_perm(mode_t posix, mode_t *win_ptr)
{
    if (win_ptr == NULL) {
        errno = EINVAL;
        return SSH_ERROR;
    }

    *win_ptr = 0;
    if ((posix & 0444) != 0) {
        /*
         * If read permission is set for user or group or others then enable
         * read permission for windows.
         */
        *win_ptr |= _S_IREAD;
    }

    if ((posix & 0222) != 0) {
        /*
         * If write permission is set for user or group or others then enable
         * write permission for windows.
         */
        *win_ptr |= _S_IWRITE;
    }

    if ((posix & 0111) != 0) {
        /*
         * If execute permission is set for user or group or others then enable
         * execute permission for windows.
         */
        *win_ptr |= _S_IEXEC;
    }

    return SSH_OK;
}

#endif /* _WIN32 */

/**
 * @internal
 *
 * @brief High level helper used to begin a data chunk transfer from a local
 * file to a remote file.
 *
 * This function :
 *
 * - Reads data from a local file.
 *
 * - Issues an async write request to write that data to a remote file.
 *
 * - Updates the file transfer structure according to the number of bytes
 *   requested to write.
 *
 * - Enqueues the sftp aio handle corresponding to the sent write request in
 *   a queue of sftp aio handles.
 *
 * @param[in] ft           sftp ft handle to a file transfer structure
 *                         corresponding to the local to remote transfer.
 *
 * @param[in] local_fd     File descriptor of the local file to read from.
 *
 * @param[in] remote_file  Open sftp file handle of the remote file to write to.
 *
 * @param[in] aio_queue    A queue of sftp aio handles in which the sftp
 *                         aio handle corresponding to the issued request
 *                         will be enqueued.
 *
 * @returns                SSH_OK on success, SSH_ERROR on error.
 */
static int ft_begin_l2r(sftp_ft ft,
                        int local_fd,
                        sftp_file remote_file,
                        struct ssh_list *aio_queue)
{
    sftp_session sftp = NULL;
    sftp_aio aio = NULL;

    uint64_t to_read;
    size_t value_res;
    int rc;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        /* should never happen */
        return SSH_ERROR;
    }

    sftp = ft->sftp;
    if (remote_file == NULL ||
        remote_file->sftp == NULL ||
        remote_file->sftp->session == NULL ||
        local_fd < 0 ||
        aio_queue == NULL) {
        /* should never happen */
        ssh_set_error_invalid(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    to_read = ft->bytes_total - ft->bytes_requested;
    if (to_read > ft->internal_chunk_size) {
        to_read = ft->internal_chunk_size;
    }

    value_res = to_read;
    rc = aio_begin_l2r(remote_file, local_fd, &value_res, &aio);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    /*
     * Update the file transfer structure based on the number of bytes for
     * which the write request was sent.
     */
    ft->bytes_requested += value_res;

    if (value_res < to_read) {
        /*
         * On success, aio_begin_l2r() giving a short read may mean two things:
         *
         * - The number of bytes requested to read from the local file exceeded
         *   the max limit for number of data bytes which can be sent by libssh
         *   in an sftp write request, and hence a lesser number of bytes were
         *   read from the local file and sent in the write request.
         * or
         * - EOF was encountered before reading the requested number of bytes
         *   from the local file.
         *
         * In our case, it would mean the latter, because if data is being
         * uploaded then the ft->internal_chunk_size won't exceed libssh's sftp
         * limit for writing.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Local source file is shorter than expected. Expected "
                      "%"PRIu64" bytes, got only %"PRIu64" bytes",
                      ft->bytes_total,
                      ft->bytes_requested);
        sftp_set_error(sftp, SSH_FX_FAILURE);

        /* This won't do anything when aio is NULL (i.e when value_res == 0) */
        SFTP_AIO_FREE(aio);

        return SSH_ERROR;
    }

    rc = ssh_list_append(aio_queue, aio);
    if (rc == SSH_ERROR) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(aio);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief High level helper used to wait for the completion of a local to
 * remote data chunk transfer.
 *
 * This function :
 *
 * - Expects the user to pass a pointer to an sftp aio handle, this aio handle
 *   should be corresponding to a previously issued write request to wait for.
 *
 * - Waits for the response of that write request.
 *
 * - Updates the file transfer structure according to the number of bytes
 *   written to the remote file due to that write request.
 *
 * - Irrespective of success or failure, deallocates the memory corresponding
 *   to the supplied aio handle and assigns NULL to that aio handle using the
 *   passed pointer to that handle.
 *
 * @param[in] ft          sftp ft handle to a file transfer structure
 *                        corresponding to the local to remote transfer.
 *
 * @param[in] aio         Pointer to an sftp aio handle which is dequeued
 *                        from an aio queue in which ft_begin_l2r() enqueues
 *                        sftp aio handles.
 *
 * @returns               SSH_OK on success, SSH_ERROR on error.
 */
static int ft_wait_l2r(sftp_ft ft, sftp_aio *aio)
{
    sftp_session sftp = NULL;
    ssize_t bytes_written;
    int rc;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        if (aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }

        return SSH_ERROR;
    }

    sftp = ft->sftp;
    if (aio == NULL || *aio == NULL) {
        ssh_set_error_invalid(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    bytes_written = sftp_aio_wait_write(aio);
    if (bytes_written == SSH_ERROR)  {
        return SSH_ERROR;
    }

    if (bytes_written == SSH_AGAIN) {
        /*
         * Should never happen as the ft api which is responsible for
         * opening and handling the remote file should not set
         * non-blocking mode for it.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Non-blocking mode set for the remote target file");
        sftp_set_error(sftp, SSH_FX_FAILURE);

        /*
         * aio_wait_*() doesn't deallocate the memory corresponding to
         * the supplied aio handle if it returns SSH_AGAIN, hence we need
         * to release that memory before returning.
         */
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    ft->bytes_transferred += bytes_written;
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Perform a local to remote file transfer.
 *
 * @param[in] ft          A sftp ft handle to a file transfer structure
 *                        corresponding to the local to remote transfer.
 *
 * @return                SSH_OK on a successful transfer,
 *                        SSH_ERROR on error.
 */
static int ft_transfer_l2r(sftp_ft ft) __attr_unused__;
static int ft_transfer_l2r(sftp_ft ft)
{
    /*
     * Initializing this by -1 is necessary for the cleanup code to work
     * correctly for the local file.
     */
    int local_fd = -1;

    struct stat local_attr = {0};

    sftp_session sftp = NULL;
    sftp_file remote_file = NULL;
    sftp_attributes remote_attr = NULL;
    sftp_aio aio = NULL;
    struct ssh_list *aio_queue = NULL;

    char errno_msg[SSH_ERRNO_MSG_MAX] = {0};
    const char *static_ssh_err_str = NULL;
    char *initial_ssh_err_str = NULL;
    int initial_ssh_err_code, initial_sftp_err_code;

    uint8_t request_err_flag = 0,
            callback_aborted_flag = 0;

    mode_t target_mode = 0;
    size_t i;
    int rc, err = SSH_ERROR;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        return err;
    }

    sftp = ft->sftp;

    /* initially */
    ft->bytes_transferred = 0;
    ft->bytes_total = 0;
    ft->bytes_skipped = 0;
    ft->bytes_requested = 0;

    rc = stat(ft->source_path, &local_attr);
    if (rc == -1) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Failed to retrieve information "
                      "about the local source file, reason : %s",
                      ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return err;
    }

    /* Check whether the local source is a regular file or not */
    if ((local_attr.st_mode & S_IFMT) != S_IFREG) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Local source file is not a regular file, "
                      "it cannot be transferred");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return err;
    }

    ft->bytes_total = local_attr.st_size;
    if (ft->resume_transfer_flag == 1) {
        /*
         * If the transfer is to be resumed, the target file
         * must exist, must be a regular file and must not
         * be larger than the source file.
         */
        remote_attr = sftp_stat(sftp, ft->target_path);
        if (remote_attr == NULL) {
            rc = sftp_get_error(sftp);
            if (rc == SSH_FX_NO_SUCH_FILE ||
                rc == SSH_FX_NO_SUCH_PATH) {
                /*
                 * Overwrite the ssh error string to a more
                 * informative message for the user as compared
                 * to SFTP SERVER : No such file or No such path.
                 */
                ssh_set_error(sftp->session, SSH_FATAL,
                              "Remote target file does not exist, "
                              "transfer cannot be resumed");
            }
            return err;
        }

        if (remote_attr->type != SSH_FILEXFER_TYPE_REGULAR) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Remote target file is not a regular file, "
                          "the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_attributes_free(remote_attr);
            return err;
        }

        if ((remote_attr->flags & SSH_FILEXFER_ATTR_SIZE) == 0) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "File attributes of the remote target file obtained "
                          "from the sftp server do not contain file size, "
                          "the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_OP_UNSUPPORTED);
            sftp_attributes_free(remote_attr);
            return err;

        }

        if (remote_attr->size > (uint64_t)local_attr.st_size) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Remote target file is larger than the local "
                          "source file, the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_attributes_free(remote_attr);
            return err;
        }

        ft->bytes_transferred = remote_attr->size;
        ft->bytes_skipped = remote_attr->size;
        ft->bytes_requested = remote_attr->size;

        sftp_attributes_free(remote_attr);
    } else {
        if (ft->target_mode != 0) {
            target_mode = ft->target_mode;
        } else {
#ifdef _WIN32
            rc = ft_win_to_posix_perm(local_attr.st_mode, &target_mode);
            if (rc == SSH_ERROR) {
                ssh_set_error(sftp->session, SSH_FATAL,
                              "Failed to convert Windows style permissions to "
                              "POSIX style permissions");
                sftp_set_error(sftp, SSH_FX_FAILURE);
                return err;
            }
#else
            target_mode = local_attr.st_mode & 0777;
#endif
        }
    }

    /* Open the source file for reading */
    local_fd = open(ft->source_path, O_RDONLY, 0);
    if (local_fd == -1) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Failed to open the local source file for reading, "
                      "reason : %s",
                      ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return err;
    }

    /* Set the read offset for the local source file */
    if (ft->bytes_skipped > 0) {
        rc = ft_lseek_from_start(local_fd, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            sftp_set_error(sftp, SSH_FX_FAILURE);
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Failed to set the file offset for "
                          "the local source file, reason : %s",
                          ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            goto out;
        }
    }

    /* Open the remote file for writing */
    remote_file = sftp_open(sftp,
                            ft->target_path,
                            O_WRONLY | O_CREAT |
                            (ft->resume_transfer_flag == 1 ? 0 : O_TRUNC),
                            target_mode);
    if (remote_file == NULL) {
        goto out;
    }

    /* Set the write offset for the remote file */
    if (ft->bytes_skipped > 0) {
        rc = sftp_seek64(remote_file, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            goto out;
        }
    }

    /* Call progress callback before starting the transfer */
    if (ft->pgrs_callback != NULL) {
        rc = ft->pgrs_callback(ft);
        if (rc != 0) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "File transfer aborted by the progress callback");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }
    }

    /* Get the ssh and sftp errors before starting the transfer */
    static_ssh_err_str = ssh_get_error(sftp->session);
    initial_ssh_err_str = strdup(static_ssh_err_str);
    if (initial_ssh_err_str == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    initial_ssh_err_code = ssh_get_error_code(sftp->session);
    initial_sftp_err_code = sftp_get_error(sftp);

    aio_queue = ssh_list_new();
    if (aio_queue == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    /* Issue in flight write requests for the local to remote transfer. */
    for (i = 0;
         i < ft->in_flight_requests &&
         ft->bytes_requested < ft->bytes_total;
         ++i) {
        rc = ft_begin_l2r(ft, local_fd, remote_file, aio_queue);
        if (rc == SSH_ERROR) {
            request_err_flag = 1;
            break;
        }
    }

    /*
     * Wait for the responses of the issued requests and issue more requests
     * if required.
     */
    while ((aio = ssh_list_pop_head(sftp_aio, aio_queue)) != NULL) {
        rc = ft_wait_l2r(ft, &aio);
        if (rc == SSH_ERROR) {
            break;
        }

        if (ft->pgrs_callback != NULL && callback_aborted_flag != 1) {
            rc = ft->pgrs_callback(ft);
            if (rc != 0) {
                callback_aborted_flag = 1;
                ssh_set_error(sftp->session, SSH_FATAL,
                              "File transfer aborted by the progress callback");
                sftp_set_error(sftp, SSH_FX_FAILURE);
            }
        }

        if (ft->bytes_requested == ft->bytes_total ||
            callback_aborted_flag == 1 ||
            request_err_flag == 1) {
            /* No need to issue more requests */
            continue;
        }

        /* else issue a request */
        rc = ft_begin_l2r(ft, local_fd, remote_file, aio_queue);
        if (rc == SSH_ERROR) {
            request_err_flag = 1;
        }
    }

    /*
     * Free the aio structures corresponding to the outstanding requests,
     * if any.
     */
    while ((aio = ssh_list_pop_head(sftp_aio, aio_queue)) != NULL) {
        SFTP_AIO_FREE(aio);
    }

    if (ft->bytes_transferred == ft->bytes_total) {
        /* File transfer was successful */

        if (callback_aborted_flag == 1) {
            /* The progress callback tried to abort the transfer
             * but getting the responses for the outstanding
             * async requests completed the transfer and
             * no other operation failed.
             *
             * We changed the ssh and sftp errors because the
             * progress callback tried to abort, but since the
             * file transfer operation is successful we restore
             * them to their previous state.
             */
            ssh_set_error(sftp->session, initial_ssh_err_code,
                          "%s", initial_ssh_err_str);
            sftp_set_error(sftp, initial_sftp_err_code);
        }
        err = SSH_OK;
    }

out:

    /* Cleanup */
    ssh_list_free(aio_queue);

    SAFE_FREE(initial_ssh_err_str);

    /*
     * It is possible that the whole transfer is a success and err is set to
     * SSH_OK, but closing of the source or target file fails.
     *
     * In this case the err is to be set back to SSH_ERROR, with ssh and sftp
     * errors set to indicate the reason for failure.
     */
    if (remote_file != NULL) {
        rc = sftp_close(remote_file);
        if (rc == SSH_ERROR) {
            err = SSH_ERROR;
        }
    }

    if (local_fd != -1) {
        rc = close(local_fd);
        if (rc == -1) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Error encountered while closing the local source "
                          "file, error : %s",
                           ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            err = SSH_ERROR;
        }
    }

    return err;
}

/**
 * @internal
 *
 * @brief Issue an async read request for a remote to local
 * file transfer and update the file transfer structure according
 * to number of bytes requested. The sftp aio handle corresponding
 * to the issued async request will be enqueued in a queue of sftp
 * aio handles.
 *
 * @param[in] ft              sftp ft handle to a file transfer structure
 *                            corresponding to the remote to local transfer.
 *
 * @param[in] remote_file     sftp file handle to a remote file from which data
 *                            is to be read.
 *
 * @param[in] aio_queue       Queue of sftp aio handles in which the sftp aio
 *                            handle corresponding to the issued request will
 *                            be enqueued on success.
 *
 * @returns                   SSH_OK on success, SSH_ERROR on error.
 *
 * @warning                   This function updates a counter present in the
 *                            file transfer structure handled by ft to keep the
 *                            track of the total number of bytes for which
 *                            async requests are issued.
 */
static int ft_begin_r2l(sftp_ft ft,
                        sftp_file remote_file,
                        struct ssh_list *aio_queue)
{
    sftp_session sftp = NULL;
    sftp_aio aio = NULL;
    size_t to_read;
    ssize_t bytes_requested;
    int rc;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        /* should never happen */
        return SSH_ERROR;
    }

    sftp = ft->sftp;
    if (remote_file == NULL ||
        remote_file->sftp == NULL ||
        remote_file->sftp->session == NULL ||
        aio_queue == NULL) {
        /* should never happen */
        ssh_set_error_invalid(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    to_read = ft->bytes_total - ft->bytes_requested;
    if (to_read > ft->internal_chunk_size) {
        to_read = ft->internal_chunk_size;
    }

    bytes_requested = sftp_aio_begin_read(remote_file, to_read, &aio);
    if (bytes_requested == SSH_ERROR) {
        return SSH_ERROR;
    }

    if ((size_t)bytes_requested < to_read) {
        /*
         * Should never happen, because if data is being downloaded then the
         * ft->internal_chunk_size (>= to_read) would be <= libssh's sftp limit
         * for reading.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "sftp_aio_begin_read() behaved incorrectly. It sent a "
                      "read request for lesser number of bytes when the number "
                      "of bytes caller asked to read (%zu) were within "
                      "libssh's sftp limit for reading (%"PRIu64")",
                      to_read, sftp->limits->max_read_length);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(aio);
        return SSH_ERROR;
    }

    ft->bytes_requested += bytes_requested;

    rc = ssh_list_append(aio_queue, aio);
    if (rc == SSH_ERROR) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(aio);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Wait for an response of an async read request issued using
 * ft_begin_r2l(), write the read data in a local file and update the
 * file transfer structure according to the number of bytes read from
 * the remote file and written to the local file.
 *
 * A pointer to a sftp aio handle should be passed while calling
 * this function. Irrespective of success or failure, this function
 * deallocates memory corresponding to the supplied aio handle and
 * assigns NULL to that aio handle using the passed pointer to that handle.
 *
 * @param[in] ft          sftp ft handle to the file transfer structure
 *                        corresponding to the remote to local transfer.
 *
 * @param[in] aio         Pointer to a sftp aio handle dequeued from an
 *                        aio queue in which ft_begin_r2l() enqueues sftp
 *                        aio handles.
 *
 * @param[in] local_fd    File descriptor of the local file in which the
 *                        data read from the remote file is to be written.
 *
 * @returns               SSH_OK on success, SSH_ERROR on error.
 *
 * @warning               This function updates a counter present in the
 *                        file transfer structure handled by ft to keep the
 *                        track of the number of total number of bytes
 *                        successfully transferred.
 *
 * @see ft_begin_r2l()
 */
static int ft_wait_r2l(sftp_ft ft, sftp_aio *aio, int local_fd)
{
    sftp_session sftp = NULL;
    ssize_t bytes_transferred;
    int rc;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        if (aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }

        return SSH_ERROR;
    }

    sftp = ft->sftp;
    if (aio == NULL || *aio == NULL || local_fd < 0) {
        /* should never happen */
        ssh_set_error_invalid(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);

        if (aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }

        return SSH_ERROR;
    }

    bytes_transferred = aio_wait_r2l(aio, local_fd);
    if (bytes_transferred == SSH_ERROR) {
        return SSH_ERROR;
    }

    if (bytes_transferred == SSH_AGAIN) {
        /*
         * Should never happen, since sftp ft api is the one
         * opening and handling the remote file and it shouldn't
         * set the remote file to non-blocking mode.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Non-blocking mode set for the remote source");
        sftp_set_error(sftp, SSH_FX_FAILURE);

        /*
         * aio_wait_*() doesn't deallocate the memory corresponding to
         * the supplied aio handle if it returns SSH_AGAIN, hence we need
         * to release that memory before returning.
         */
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    ft->bytes_transferred += bytes_transferred;

    if (ft->bytes_transferred != ft->bytes_total &&
        (size_t)bytes_transferred != ft->internal_chunk_size) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Remote source file is shorter than expected. Expected "
                      "%"PRIu64" bytes, got only %"PRIu64" bytes",
                      ft->bytes_total,
                      ft->bytes_transferred);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Perform a remote to local file transfer.
 *
 * @param[in] ft          sftp ft handle to a file transfer structure
 *                        corresponding to the remote to local transfer.
 *
 * @returns               SSH_OK on success, SSH_ERROR on error.
 */
static int ft_transfer_r2l(sftp_ft ft) __attr_unused__;
static int ft_transfer_r2l(sftp_ft ft)
{
    sftp_session sftp = NULL;
    sftp_attributes remote_attr = NULL;
    sftp_file remote_file = NULL;
    sftp_aio aio = NULL;
    struct ssh_list *aio_queue = NULL;

    /*
     * Initializing this by -1 is necessary for the cleanup code to work
     * correctly for the local file.
     */
    int local_fd = -1;

    struct stat local_attr = {0};

    const char *static_ssh_err_str = NULL;
    char *initial_ssh_err_str = NULL;
    int initial_ssh_err_code, initial_sftp_err_code;
    char errno_msg[SSH_ERRNO_MSG_MAX] = {0};

    uint8_t request_err_flag = 0,
            callback_aborted_flag = 0;

    mode_t target_mode = 0;
    size_t i;
    int rc, err = SSH_ERROR;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        return err;
    }

    sftp = ft->sftp;

    /* initially */
    ft->bytes_total = 0;
    ft->bytes_transferred = 0;
    ft->bytes_skipped = 0;
    ft->bytes_requested = 0;

    /* Get the remote source's file size */
    remote_attr = sftp_stat(sftp, ft->source_path);
    if (remote_attr == NULL) {
        return err;
    }

    if (remote_attr->type != SSH_FILEXFER_TYPE_REGULAR) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Remote source file is not a regular file, "
                      "it cannot be transferred");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        sftp_attributes_free(remote_attr);
        goto out;
    }

    if ((remote_attr->flags & SSH_FILEXFER_ATTR_SIZE) == 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "File attributes of the remote source file obtained from "
                      "the sftp server do not contain file size, the remote "
                      "source file cannot be transferred");
        sftp_set_error(sftp, SSH_FX_OP_UNSUPPORTED);
        goto out;
    }
    ft->bytes_total = remote_attr->size;

    if (ft->resume_transfer_flag == 1) {
        /*
         * If the transfer is to be resumed, the local target file must exist,
         * must be a regular file and must not be larger than the remote source
         * file.
         */
        rc = stat(ft->target_path, &local_attr);
        if (rc == -1) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Failed to retrieve the file attributes of the "
                          "local target file, reason : %s. The transfer cannot "
                          "be resumed",
                          ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }

        if ((local_attr.st_mode & S_IFMT) != S_IFREG) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Local target file is not a regular file, "
                          "the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }

        if ((uint64_t)local_attr.st_size > remote_attr->size) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Local target file is larger than the remote "
                          "source file, the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }

        ft->bytes_transferred = local_attr.st_size;
        ft->bytes_skipped = local_attr.st_size;
        ft->bytes_requested = local_attr.st_size;
    } else {

        if (ft->target_mode != 0) {
            target_mode = ft->target_mode;
        } else if ((remote_attr->permissions &
                    SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
#ifdef _WIN32
            rc = ft_posix_to_win_perm(remote_attr->permissions, &target_mode);
            if (rc == SSH_ERROR) {
                ssh_set_error(sftp->session, SSH_FATAL,
                              "Failed to convert POSIX style permissions to "
                              "Windows style permissions");
                sftp_set_error(sftp, SSH_FX_FAILURE);
                goto out;
            }

            /*
             * Ensure that the execute permission flag is unset as _open() on
             * Windows behaves badly if a value other than some combination of
             * _S_IREAD and _S_IWRITE is passed as the permission mode.
             */
            target_mode &= ~_S_IEXEC;
#else
            target_mode = remote_attr->permissions & 0777;
#endif
        } else {
#ifdef _WIN32
            target_mode = _S_IREAD | _S_IWRITE;
#else
            target_mode = S_IRUSR | S_IWUSR |
                          S_IRGRP | S_IWGRP |
                          S_IROTH | S_IWOTH;
#endif
        }
    }

    /* Open the remote source file for reading */
    remote_file = sftp_open(sftp, ft->source_path, O_RDONLY, 0);
    if (remote_file == NULL) {
        goto out;
    }

    /* Set the read offset for the remote source file */
    if (ft->bytes_skipped > 0) {
        rc = sftp_seek64(remote_file, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            goto out;
        }
    }

    /* Open the local target file for writing */
    local_fd = open(ft->target_path,
                    O_WRONLY | O_CREAT |
                    (ft->resume_transfer_flag ? 0 : O_TRUNC),
                    target_mode);

    if (local_fd == -1) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Failed to open the local target file for reading, "
                      "reason : %s",
                      ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    /* Set the write offset for the local target file */
    if (ft->bytes_skipped > 0) {
        rc = ft_lseek_from_start(local_fd, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Failed to set the file offset for the local "
                          "target file, reason : %s\n",
                          ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }
    }

    /* Call the progress callback before starting the transfer */
    if (ft->pgrs_callback != NULL) {
        rc = ft->pgrs_callback(ft);
        if (rc != 0) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "File transfer aborted by the progress callback");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }
    }

    /* Get the ssh and sftp errors before starting the transfer */
    static_ssh_err_str = ssh_get_error(sftp->session);
    initial_ssh_err_str = strdup(static_ssh_err_str);
    if (initial_ssh_err_str == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    initial_ssh_err_code = ssh_get_error_code(sftp->session);
    initial_sftp_err_code = sftp_get_error(sftp);

    aio_queue = ssh_list_new();
    if (aio_queue == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    /* Issue in flight read requests for the remote source */
    for (i = 0;
         i < ft->in_flight_requests && ft->bytes_requested < ft->bytes_total;
         ++i) {
        rc = ft_begin_r2l(ft, remote_file, aio_queue);
        if (rc == SSH_ERROR) {
            request_err_flag = 1;
            break;
        }
    }

    /*
     * Get the response for the outstanding read requests
     * and issue more requests if required.
     */
    while ((aio = ssh_list_pop_head(sftp_aio, aio_queue)) != NULL) {
        rc = ft_wait_r2l(ft, &aio, local_fd);
        if (rc == SSH_ERROR) {
            break;
        }

        if (ft->pgrs_callback != NULL && callback_aborted_flag != 1) {
            rc = ft->pgrs_callback(ft);
            if (rc != 0) {
                callback_aborted_flag = 1;
                ssh_set_error(sftp->session, SSH_FATAL,
                              "File transfer aborted by the progress callback");
                sftp_set_error(sftp, SSH_FX_FAILURE);
            }
        }

        if (ft->bytes_requested == ft->bytes_total ||
           request_err_flag == 1 ||
           callback_aborted_flag == 1) {
           /* No need to issue more requests */
           continue;
       }

       /* else issue a request */
       rc = ft_begin_r2l(ft, remote_file, aio_queue);
       if (rc == SSH_ERROR) {
           request_err_flag = 1;
       }
    }

    /*
     * Free the aio structures corresponding to the outstanding requests,
     * if any.
     */
    while ((aio = ssh_list_pop_head(sftp_aio, aio_queue)) != NULL) {
        SFTP_AIO_FREE(aio);
    }

    if (ft->bytes_transferred == ft->bytes_total) {
        /* File transfer was successful */
        if (callback_aborted_flag == 1) {
            /*
             * The progress callback tried to abort the transfer
             * but getting the responses for the outstanding
             * async requests completed the transfer and
             * no other operation failed.
             *
             * We changed the ssh and sftp errors because the
             * progress callback tried to abort, but since the
             * file transfer operation is successful we restore
             * them to their previous state.
             */
            ssh_set_error(sftp->session, initial_ssh_err_code,
                          "%s", initial_ssh_err_str);
            sftp_set_error(sftp, initial_sftp_err_code);
        }

        err = SSH_OK;
    }

out:
    /* Cleanup */
    ssh_list_free(aio_queue);
    SAFE_FREE(initial_ssh_err_str);

    /*
     * It is possible that the whole transfer is a success and err is set to
     * SSH_OK, but closing of the source or target file fails.
     *
     * In this case the err is to be set back to SSH_ERROR, with ssh and sftp
     * errors set to indicate the reason for the failure.
     */
    if (local_fd != -1) {
        rc = close(local_fd);
        if (rc == -1) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Error encountered while closing the "
                          "local target file, error : %s",
                          ssh_strerror(errno, errno_msg, sizeof(errno_msg)));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            err = SSH_ERROR;
        }
    }

    if (remote_file != NULL) {
        rc = sftp_close(remote_file);
        if(rc == SSH_ERROR) {
            err = SSH_ERROR;
        }
    }

    sftp_attributes_free(remote_attr);

    return err;
}

/**
 * @internal
 *
 * @brief Wait for an async remote read to complete and begin an async remote
 * write. Enqueue the sftp aio handle corresponding to sent async write request
 * in a queue of sftp aio handles.
 *
 * A pointer to a sftp aio handle should be passed while calling this function.
 * Irrespective of success or failure, this function deallocates memory
 * corresponding to the supplied aio handle and assigns NULL to that aio handle
 * using the passed pointer to that handle.
 *
 * @param ft[in]                  sftp ft handle to a file transfer structure
 *                                corresponding to the remote to remote
 *                                transfer.
 *
 * @param aio[in]                 Pointer to a sftp aio handle dequeued from an
 *                                aio queue in which ft_begin_r2l() enqueues
 *                                sftp aio handles.
 *
 * @param bytes_down[in, out]     Pointer to a counter to keep the track of the
 *                                number of bytes downloaded from the remote
 *                                source file, it is updated appropriately as
 *                                the bytes are downloaded from the remote
 *                                source file.
 *
 * @param file_out[in]            The open sftp file handle to write to.
 *
 * @param up_aio_queue[in]        A queue of sftp aio handles in which the sftp
 *                                aio handle corresponding to the sent write
 *                                request will be enqueued.
 *
 * @returns                       SSH_OK on success, SSH_ERROR on error.
 *
 * @see ft_begin_r2l()
 */
static int ft_wait_begin_r2r(sftp_ft ft,
                             sftp_aio *aio,
                             uint64_t *bytes_down,
                             sftp_file file_out,
                             struct ssh_list *up_aio_queue)
{
    sftp_session sftp = NULL;
    ssize_t bytes;
    int rc;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        if (aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }

        return SSH_ERROR;
    }

    sftp = ft->sftp;

    if (aio == NULL || *aio == NULL ||
        bytes_down == NULL || file_out == NULL || up_aio_queue == NULL) {
        ssh_set_error_invalid(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);

        if (aio != NULL) {
            SFTP_AIO_FREE(*aio);
        }

        return SSH_ERROR;
    }

    bytes = aio_wait_begin_r2r(aio, file_out);
    if (bytes == SSH_ERROR) {
        return SSH_ERROR;
    }

    if (bytes == SSH_AGAIN) {
        /*
         * Should never happen, since sftp ft api is the one
         * opening and handling the remote source file and it shouldn't
         * set non-blocking mode for the remote source file.
         */
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Non-blocking mode set for the remote source file");
        sftp_set_error(sftp, SSH_FX_FAILURE);

        /*
         * aio_wait_*() doesn't deallocate the memory corresponding to
         * the supplied aio handle if it returns SSH_AGAIN, hence we need
         * to release that memory before returning.
         */
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    *bytes_down += bytes;
    if (*bytes_down != ft->bytes_total &&
        (size_t)bytes != ft->internal_chunk_size) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Remote source file is shorter than expected. Expected "
                      "%"PRIu64" bytes, got %"PRIu64" bytes",
                      ft->bytes_total,
                      *bytes_down);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    rc = ssh_list_append(up_aio_queue, *aio);
    if (rc == SSH_ERROR) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        SFTP_AIO_FREE(*aio);
        return SSH_ERROR;
    }

    /*
     * Store NULL at the pointed location, as the sftp aio handle present at
     * that location has been stored in the queue.
     */
    *aio = NULL;

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Perform a remote to remote file transfer.
 *
 * @param ft          sftp ft handle to a file transfer structure corresponding
 *                    to the remote to remote transfer.
 *
 * @returns           SSH_OK on success, SSH_ERROR on error.
 */
static int ft_transfer_r2r(sftp_ft ft) __attr_unused__;
static int ft_transfer_r2r(sftp_ft ft)
{
    sftp_session sftp = NULL;
    sftp_file file_in = NULL, file_out = NULL;
    sftp_attributes attr_in = NULL, attr_out = NULL;
    sftp_aio aio = NULL;
    struct ssh_list *down_aio_queue = NULL, *up_aio_queue = NULL;

    const char *static_ssh_err_str = NULL;
    char *initial_ssh_err_str = NULL;
    int initial_ssh_err_code, initial_sftp_err_code;

    uint8_t callback_aborted_flag = 0,
            down_req_err_flag = 0,
            up_req_err_flag = 0;

    mode_t target_mode = 0;
    int64_t len_copy;
    uint64_t bytes_downloaded = 0;
    size_t i;
    int rc, err = SSH_ERROR;

    rc = ft_validate(ft);
    if (rc == SSH_ERROR) {
        return err;
    }

    sftp = ft->sftp;

    /* initially */
    ft->bytes_total = 0;
    ft->bytes_transferred = 0;
    ft->bytes_skipped = 0;
    ft->bytes_requested = 0;

    attr_in = sftp_stat(sftp, ft->source_path);
    if (attr_in == NULL) {
        return err;
    }

    if (attr_in->type != SSH_FILEXFER_TYPE_REGULAR) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "Remote source file is not a regular file, "
                      "the transfer cannot be performed");
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    if ((attr_in->flags & SSH_FILEXFER_ATTR_SIZE) == 0) {
        ssh_set_error(sftp->session, SSH_FATAL,
                      "File attributes of the remote source file obtained from "
                      "the sftp server do not contain the file size, the "
                      "transfer cannot be performed");
        sftp_set_error(sftp, SSH_FX_OP_UNSUPPORTED);
        goto out;
    }

    ft->bytes_total = attr_in->size;

    if (ft->resume_transfer_flag == 1) {
        /*
         * If the transfer is to be resumed, the target file
         * must exist, must be a regular file and must not
         * be larger than the source file.
         */
        attr_out = sftp_stat(sftp, ft->target_path);
        if (attr_out == NULL) {
            rc = sftp_get_error(sftp);
            if (rc == SSH_FX_NO_SUCH_FILE ||
                rc == SSH_FX_NO_SUCH_PATH) {
                /*
                 * Overwrite the ssh error string to a more
                 * informative message for the user as compared
                 * to SFTP SERVER : No such file or No such path.
                 */
                ssh_set_error(sftp->session, SSH_FATAL,
                              "Remote target file does not exist, "
                              "the transfer cannot be resumed");
            }

            goto out;
        }

        if (attr_out->type != SSH_FILEXFER_TYPE_REGULAR) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Remote target file is not a regular file, "
                          "the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_attributes_free(attr_out);
            goto out;
        }

        if ((attr_out->flags & SSH_FILEXFER_ATTR_SIZE) == 0) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "File attributes of the remote target file obtained "
                          "from the sftp server do not contain the file size, "
                          "the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_OP_UNSUPPORTED);
            sftp_attributes_free(attr_out);
            goto out;
        }

        if (attr_out->size > attr_in->size) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "Remote target file is larger than the remote "
                          "source file, the transfer cannot be resumed");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            sftp_attributes_free(attr_out);
            goto out;
        }

        ft->bytes_transferred = attr_out->size;
        ft->bytes_requested = attr_out->size;
        ft->bytes_skipped = attr_out->size;
        bytes_downloaded = attr_out->size;

        sftp_attributes_free(attr_out);
    } else {

        if (ft->target_mode != 0) {
            target_mode = ft->target_mode;
        } else if ((attr_in->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            target_mode = attr_in->permissions & 0777;
        } else {
            target_mode = 0666;
        }
    }

    /* Open the remote source file for reading */
    file_in = sftp_open(sftp, ft->source_path, O_RDONLY, 0);
    if (file_in == NULL) {
        goto out;
    }

    /* Set the read offset for the remote source file */
    if (ft->bytes_skipped > 0) {
        rc = sftp_seek64(file_in, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            goto out;
        }
    }

    /* Open the remote target file for writing */
    file_out = sftp_open(sftp, ft->target_path,
                         O_WRONLY | O_CREAT |
                         (ft->resume_transfer_flag == 1 ? 0 : O_TRUNC),
                         target_mode);
    if (file_out == NULL) {
        goto out;
    }

    /* Set the write offset for the remote target file */
    if (ft->bytes_skipped > 0) {
        rc = sftp_seek64(file_out, ft->bytes_skipped);
        if (rc == SSH_ERROR) {
            goto out;
        }
    }

    /* Call the progress callback before starting the transfer */
    if (ft->pgrs_callback != NULL) {
        rc = ft->pgrs_callback(ft);
        if (rc != 0) {
            ssh_set_error(sftp->session, SSH_FATAL,
                          "File transfer aborted by the progress callback");
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }
    }

    rc = sftp_extension_supported(sftp, "copy-data", "1");
    if (rc == 1) {
        len_copy = sftp_copy_file_range(file_in, NULL, file_out, NULL, 0);
        if (len_copy == SSH_ERROR) {
            goto out;
        }

        if ((uint64_t)len_copy != (ft->bytes_total - ft->bytes_skipped)) {
            ssh_set_error(sftp, SSH_FATAL,
                          "Remote source file is shorter than expected, "
                          "expected %"PRIu64" bytes, got only %"PRIu64" bytes",
                          ft->bytes_total,
                          (ft->bytes_skipped + (uint64_t)len_copy));
            sftp_set_error(sftp, SSH_FX_FAILURE);
            goto out;
        }

        ft->bytes_transferred = ft->bytes_total;
        ft->bytes_requested = ft->bytes_total;

        if (ft->pgrs_callback != NULL) {
            /*
             * Ignoring the callback's return value here as the transfer
             * has already completed successfully.
             */
            ft->pgrs_callback(ft);
        }

        err = SSH_OK;
        goto out;
    }

    /*
     * If the "copy-data" extension isn't supported, then we need to download
     * chunks from the remote source file and upload them to the remote target
     * file.
     *
     * ft_begin_r2l() has been used to issue a download request.
     *
     * ft_wait_begin_r2r() has been used to wait for the response of a download
     * request and issue an upload request for the downloaded data.
     *
     * ft_wait_l2r() has been used to wait for the response of a upload request.
     */

    /* Get the initial ssh and sftp errors */
    static_ssh_err_str = ssh_get_error(sftp->session);
    initial_ssh_err_str = strdup(static_ssh_err_str);
    if (initial_ssh_err_str == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    initial_ssh_err_code = ssh_get_error_code(sftp->session);
    initial_sftp_err_code = sftp_get_error(sftp);

    down_aio_queue = ssh_list_new();
    if (down_aio_queue == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    up_aio_queue = ssh_list_new();
    if (up_aio_queue == NULL) {
        ssh_set_error_oom(sftp->session);
        sftp_set_error(sftp, SSH_FX_FAILURE);
        goto out;
    }

    /* Issue in-flight download requests */
    for (i = 0;
         i < ft->in_flight_requests && ft->bytes_requested < ft->bytes_total;
         ++i) {
        rc = ft_begin_r2l(ft, file_in, down_aio_queue);
        if (rc == SSH_ERROR) {
            down_req_err_flag = 1;
            break;
        }
    }

    /*
     * Get the responses of the issued download requests and issue in-flight
     * upload requests for the downloaded data. Issue more download requests if
     * needed.
     */
    for (i = 0;
         i < ft->in_flight_requests &&
         (aio = ssh_list_pop_head(sftp_aio, down_aio_queue)) != NULL;
         ++i) {
        rc = ft_wait_begin_r2r(ft,
                               &aio,
                               &bytes_downloaded,
                               file_out,
                               up_aio_queue);
        if (rc == SSH_ERROR) {
            up_req_err_flag = 1;
            break;
        }

        if (ft->bytes_requested == ft->bytes_total ||
            down_req_err_flag == 1) {
            /* No need to issue more download requests */
            continue;
        }

        /* else issue a download request */
        rc = ft_begin_r2l(ft, file_in, down_aio_queue);
        if (rc == SSH_ERROR) {
            down_req_err_flag = 1;
        }
    }

    /*
     * At this point we have in-flight upload and download requests.
     *
     * Get responses for the issued upload and download requests, issue
     * upload requests corresponding to the downloaded data and issue
     * more download requests if needed.
     */
    while ((aio = ssh_list_pop_head(sftp_aio, up_aio_queue)) != NULL) {
        rc = ft_wait_l2r(ft, &aio);
        if (rc == SSH_ERROR) {
            break;
        }

        if (ft->pgrs_callback != NULL && callback_aborted_flag != 1) {
            rc = ft->pgrs_callback(ft);
            if (rc != 0) {
                callback_aborted_flag = 1;
                ssh_set_error(sftp->session, SSH_FATAL,
                              "File transfer aborted by the progress callback");
                sftp_set_error(sftp, SSH_FX_FAILURE);
            }
        }

        /*
         * Wait for the response of a request present in the download queue and
         * issue an upload request corresponding to that download response.
         */
        if (up_req_err_flag != 1) {
            aio = ssh_list_pop_head(sftp_aio, down_aio_queue);
            if (aio != NULL) {
                rc = ft_wait_begin_r2r(ft,
                                       &aio,
                                       &bytes_downloaded,
                                       file_out,
                                       up_aio_queue);
                if (rc == SSH_ERROR) {
                    up_req_err_flag = 1;
                }
            }
        }

        if (ft->bytes_requested == ft->bytes_total ||
            callback_aborted_flag == 1 ||
            down_req_err_flag == 1 ||
            up_req_err_flag == 1) {
            /* No need to issue more download requests */
            continue;
        }

        /* else issue a download request */
        rc = ft_begin_r2l(ft, file_in, down_aio_queue);
        if (rc == SSH_ERROR) {
            down_req_err_flag = 1;
        }
    }

    /* Free the aio structures corresponding to the outstanding requests */
    while ((aio = ssh_list_pop_head(sftp_aio, down_aio_queue)) != NULL) {
        SFTP_AIO_FREE(aio);
    }

    while ((aio = ssh_list_pop_head(sftp_aio, up_aio_queue)) != NULL) {
        SFTP_AIO_FREE(aio);
    }

    if (ft->bytes_transferred == ft->bytes_total) {
        /* File transfer was successful */
        if (callback_aborted_flag == 1) {
            /*
             * The progress callback tried to abort the transfer
             * but getting the responses for the outstanding
             * async requests completed the transfer and
             * no other operation failed.
             *
             * We changed the ssh and sftp errors because the
             * progress callback tried to abort, but since the
             * file transfer operation is successful we restore
             * them to their previous state.
             */
            ssh_set_error(sftp->session, initial_ssh_err_code,
                          "%s", initial_ssh_err_str);
            sftp_set_error(sftp, initial_sftp_err_code);
        }

        err = SSH_OK;
    }

out:
    ssh_list_free(up_aio_queue);
    ssh_list_free(down_aio_queue);
    SAFE_FREE(initial_ssh_err_str);

    /*
     * It is possible that the whole transfer is a success and err is set to
     * SSH_OK, but closing of the source or target file fails.
     *
     * In this case the err is to be set back to SSH_ERROR.
     */
    if (file_out != NULL) {
        rc = sftp_close(file_out);
        if (rc == SSH_ERROR) {
            err = SSH_ERROR;
        }
    }

    if (file_in != NULL) {
        rc = sftp_close(file_in);
        if (rc == SSH_ERROR) {
            err = SSH_ERROR;
        }
    }

    sftp_attributes_free(attr_in);

    return err;
}

#endif /* WITH_SFTP */
