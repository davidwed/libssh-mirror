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

#endif /* WITH_SFTP */
