/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef GSSAPI_H_
#define GSSAPI_H_

#include "config.h"
#ifdef WITH_GSSAPI
#include "session.h"
#include <gssapi/gssapi.h>

/* all OID begin with the tag identifier + length */
#define SSH_OID_TAG 06

#define GSSAPI_KEY_EXCHANGE_SUPPORTED \
    "gss-group14-sha256-,gss-group16-sha512-,"

typedef struct ssh_gssapi_struct *ssh_gssapi;

#ifdef __cplusplus
extern "C" {
#endif

/** current state of an GSSAPI authentication */
enum ssh_gssapi_state_e {
    SSH_GSSAPI_STATE_NONE, /* no status */
    SSH_GSSAPI_STATE_RCV_TOKEN, /* Expecting a token */
    SSH_GSSAPI_STATE_RCV_MIC, /* Expecting a MIC */
};

struct ssh_gssapi_struct{
    enum ssh_gssapi_state_e state; /* current state */
    gss_cred_id_t server_creds; /* credentials of server */
    gss_cred_id_t client_creds; /* creds delegated by the client */
    gss_ctx_id_t ctx; /* the authentication context */
    gss_name_t client_name; /* Identity of the client */
    char *user; /* username of client */
    char *canonic_user; /* canonic form of the client's username */
    struct {
        gss_name_t server_name; /* identity of server */
        OM_uint32 flags; /* flags used for init context */
        gss_OID oid; /* mech being used for authentication */
        gss_cred_id_t creds; /* creds used to initialize context */
        gss_cred_id_t client_deleg_creds; /* delegated creds (const, not freeable) */
    } client;
};

#ifdef WITH_SERVER
int ssh_gssapi_handle_userauth(ssh_session session, const char *user, uint32_t n_oid, ssh_string *oids);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_server);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic);
int ssh_gssapi_server_oids(gss_OID_set *selected);
#endif /* WITH_SERVER */

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_client);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_response);


int ssh_gssapi_init(ssh_session session);
void ssh_gssapi_log_error(int verb, const char *msg_a, int maj_stat, int min_stat);
int ssh_gssapi_auth_mic(ssh_session session);
void ssh_gssapi_free(ssh_session session);
int ssh_gssapi_client_identity(ssh_session session, gss_OID_set *valid_oids);
char *ssh_gssapi_name_to_char(gss_name_t name);
int ssh_gssapi_import_name(struct ssh_gssapi_struct *gssapi, const char *host);
OM_uint32 ssh_gssapi_init_ctx(struct ssh_gssapi_struct *gssapi,
                    gss_buffer_desc *input_token,
                    gss_buffer_desc *output_token,
                    OM_uint32 *ret_flags);

char *ssh_gssapi_oid_hash(ssh_string oid);
char *ssh_gssapi_kex_mechs(ssh_session session, const char *gss_algs);
int ssh_gssapi_check_client_config(ssh_session session);
ssh_buffer ssh_gssapi_build_mic(ssh_session session, const char *context);
int ssh_gssapi_auth_keyex_mic(ssh_session session, gss_buffer_desc *mic_token_buf);

#ifdef __cplusplus
}
#endif

#endif /* WITH_GSSAPI */
#endif /* GSSAPI_H */
