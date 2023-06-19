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

#endif /* WITH_SFTP */
