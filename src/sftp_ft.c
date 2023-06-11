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

#endif /* WITH_SFTP */
