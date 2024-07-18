/*
 * dh-gss.c - diffie-hellman GSSAPI key exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2024 by Gauravsingh Sisodia <xaerru@gmail.com>
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

#include <stdio.h>
#include <gssapi/gssapi.h>
#include "libssh/gssapi.h"

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/dh.h"
#include "libssh/ssh2.h"
#include "libssh/dh-gss.h"

static SSH_PACKET_CALLBACK(ssh_packet_client_gss_dh_reply);

static ssh_packet_callback gss_dh_client_callbacks[]= {
    ssh_packet_client_gss_dh_reply
};

static struct ssh_packet_callbacks_struct ssh_gss_dh_client_callbacks = {
    .start = SSH2_MSG_KEXGSS_COMPLETE,
    .n_callbacks = 1,
    .callbacks = gss_dh_client_callbacks,
    .user = NULL
};

/** @internal
 * @brief Starts gssapi key exchange
 */
int ssh_client_gss_dh_init(ssh_session session){
    struct ssh_crypto_struct *crypto = session->next_crypto;
#if !defined(HAVE_LIBCRYPTO) || OPENSSL_VERSION_NUMBER < 0x30000000L
    const_bignum pubkey;
#else
    bignum pubkey = NULL;
#endif /* OPENSSL_VERSION_NUMBER */
    int rc;
    gss_OID_set selected = GSS_C_NO_OID_SET; /* oid selected for authentication */
    OM_uint32 maj_stat, min_stat;
    const char *gss_host = session->opts.host;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 oflags;

    rc = ssh_dh_init_common(crypto);
    if (rc == SSH_ERROR) {
        goto error;
    }

    rc = ssh_dh_keypair_gen_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR);
    if (rc == SSH_ERROR) {
        goto error;
    }
    rc = ssh_dh_keypair_get_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR, NULL, &pubkey);
    if (rc != SSH_OK) {
        goto error;
    }

    /* TODO: Make generic GSSAPI functions to avoid repetition */
    rc = ssh_gssapi_init(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    if (session->opts.gss_server_identity != NULL) {
        gss_host = session->opts.gss_server_identity;
    }

    rc = ssh_gssapi_import_name(session, gss_host);
    if (rc != SSH_OK) {
        return SSH_AUTH_DENIED;
    }

    rc = ssh_gssapi_client_identity(session, &selected);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_DENIED;
    }

    session->gssapi->client.flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
    maj_stat = ssh_gssapi_init_ctx(session, &input_token, &output_token, &oflags);
    gss_release_oid_set(&min_stat, &selected);
    if(GSS_ERROR(maj_stat)) {
        ssh_gssapi_log_error(SSH_LOG_DEBUG,
                             "Initializing gssapi context",
                             maj_stat,
                             min_stat);
        goto error;
    }

    rc = ssh_buffer_pack(session->out_buffer, "bdPB",
                       SSH2_MSG_KEXGSS_INIT,
                       output_token.length,
                       (size_t)output_token.length,
                       output_token.value,
                       pubkey);
    if (rc != SSH_OK) {
        goto error;
    }
    gss_release_buffer(&min_stat, &output_token);
#if defined(HAVE_LIBCRYPTO) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    bignum_safe_free(pubkey);
#endif

    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_gss_dh_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;

    rc = ssh_packet_send(session);
    return rc;
error:
#if defined(HAVE_LIBCRYPTO) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    bignum_safe_free(pubkey);
#endif
    ssh_dh_cleanup(crypto);
    return SSH_ERROR;
}

static void ssh_client_gss_dh_remove_callbacks(ssh_session session)
{
    ssh_packet_remove_callbacks(session, &ssh_gss_dh_client_callbacks);
}

SSH_PACKET_CALLBACK(ssh_packet_client_gss_dh_reply){
    struct ssh_crypto_struct *crypto=session->next_crypto;
    ssh_string pubkey_blob = NULL, mic = NULL, otoken = NULL;
    uint8_t b;
    bignum server_pubkey;
    int rc;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 oflags;
    OM_uint32 maj_stat;

    (void)type;
    (void)user;

    ssh_client_gss_dh_remove_callbacks(session);

    rc = ssh_buffer_unpack(packet,
                           "BSbS",
                           &server_pubkey,
                           &mic,
                           &b,
                           &otoken);
    if (rc == SSH_ERROR) {
        goto error;
    }
    session->gssapi_key_exchange_mic = mic;
    input_token.length = ssh_string_len(otoken);
    input_token.value = ssh_string_data(otoken);
    maj_stat = ssh_gssapi_init_ctx(session, &input_token, &output_token, &oflags);
    if (maj_stat != GSS_S_COMPLETE) {
        goto error;
    }
    SSH_STRING_FREE(otoken);
    rc = ssh_dh_keypair_set_keys(crypto->dh_ctx, DH_SERVER_KEYPAIR,
                               NULL, server_pubkey);
    if (rc != SSH_OK) {
        SSH_STRING_FREE(pubkey_blob);
        bignum_safe_free(server_pubkey);
        goto error;
    }

    rc = ssh_dh_compute_shared_secret(session->next_crypto->dh_ctx,
                                    DH_CLIENT_KEYPAIR, DH_SERVER_KEYPAIR,
                                    &session->next_crypto->shared_secret);
    ssh_dh_debug_crypto(session->next_crypto);
    if (rc == SSH_ERROR){
        ssh_set_error(session, SSH_FATAL, "Could not generate shared secret");
        goto error;
    }

    /* Send the MSG_NEWKEYS */
    rc = ssh_packet_send_newkeys(session);
    if (rc == SSH_ERROR) {
        goto error;
    }
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    return SSH_PACKET_USED;
error:
    ssh_dh_cleanup(session->next_crypto);
    session->session_state=SSH_SESSION_STATE_ERROR;
    return SSH_PACKET_USED;
}
