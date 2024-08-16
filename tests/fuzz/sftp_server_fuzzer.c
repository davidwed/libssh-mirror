/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/sftp.h>
#include <libssh/sftpserver.h>
#include <libssh/callbacks.h>

struct channel_data_structs
{
    ssh_event event;
    sftp_session sftp;
};

struct session_data_struct
{
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
};

static int auth_none(ssh_session session,const char *user,
          void *userdata){

    struct session_data_struct *sdata = (struct session_data_struct*)userdata;

    (void)user;
    (void)session;

    sdata->authenticated = 1;
    sdata->auth_attempts++;

    return SSH_AUTH_SUCCESS;
}

static ssh_channel channel_open(ssh_session session, void *userdata){
    struct session_data_struct *sdata = (struct session_data_struct *)userdata;

    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size)
{
    int socket_fds[2] ={-1,1};
    ssize_t nwritten;
    bool no = false;
    const char *env = NULL;
    int timeout = 1;
    int rc;
    int n;

    struct channel_data_structs c_data = {
        .sftp = NULL,
    };

    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_none_function = auth_none,
        .channel_open_request_session_function = channel_open,
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &(c_data.sftp),
        .channel_data_function = sftp_channel_default_data_callback,
        .channel_subsystem_request_function = sftp_channel_default_subsystem_request,
    };

    if (size > 219264) {
        return -1;
    }

    rc = socketpair(AF_UNIX,SOCK_STREAM,0,socket_fds);
    assert(rc ==0);

    nwritten = send(socket_fds[1],data,size,0);
    assert((size_t)nwritten == size);

    rc = shutdown(socket_fds[1],SHUT_WR);
    assert(rc == 0);

    /* Initialise the SSH server */
    ssh_bind sshbind = ssh_bind_new();
    assert(sshbind != NULL);

    ssh_session session = ssh_new();
    assert(session != NULL);

    env = getenv("LIBSSH_VERBOSITY");
    if (env != NULL && strlen(env) > 0) {
        rc = ssh_bind_options_set(sshbind,
                                  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
                                  env);
        assert(rc == 0);
    }
    rc = ssh_bind_options_set(sshbind,
                              SSH_BIND_OPTIONS_HOSTKEY,
                              "/tmp/libssh_fuzzer_private_key");
    assert(rc == 0);
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_C_S, "none");
    assert(rc == 0);
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_S_C, "none");
    assert(rc == 0);
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_C_S, "none");
    assert(rc == 0);
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_S_C, "none");
    assert(rc == 0);
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);
    assert(rc == 0);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE);

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);
    ssh_set_server_callbacks(session,&server_cb);

    rc = ssh_bind_accept_fd(sshbind,session,socket_fds[0]);
    assert(rc != SSH_ERROR);

    ssh_event event = ssh_event_new();
    assert(event != NULL);

    rc = ssh_handle_key_exchange(session);
    assert(rc == SSH_OK);

    ssh_event_add_session(event,session);

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL){
        if (sdata.auth_attempts >= 3 || n > 100) {
            break;
        }

        if (ssh_event_dopoll(event,100) == SSH_ERROR){
            break;
        }

        n++;
    }

    while (ssh_channel_is_open(sdata.channel)){
        if (ssh_event_dopoll(event,100) == SSH_ERROR){
            break;
        }

        if (c_data.event != NULL){
            continue;
        }
    }

    ssh_channel_close(sdata.channel);
    ssh_event_free(event);

    close(socket_fds[0]);
    close(socket_fds[1]);

    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);

    return 0;
}
