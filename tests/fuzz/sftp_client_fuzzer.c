/*
* Copyright 2022 Jakub Jelen <jjelen@redhat.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define LIBSSH_STATIC 1

#include <libssh/sftp.h>
#include <libssh/sftp_priv.h>
#include <libssh/sftpserver.h>

// ideally fuzz would contain two parts
// 1. Setup of fuzzer
// 2. loop of fuzz


int LLVMFUzzerTestOneInput(const uint8_t *data, size_t size){
    ssh_session session;
    sftp_session sftp;
    int nwritten;
    char *env;
    int socket_fds[2] = {-1,1};
    int rc;

    rc = socketpair(AF_UNIX,SOCK_STREAM,0,socket_fds);
    assert(rc==0);

    nwritten = send(socket_fds[1],data,size,0);
    assert((size_t)nwritten == size);

    rc = shutdown(socket_fds[1],SHUT_WR);
    assert((rc == 0));

    ssh_init();

    session = ssh_new();
    assert(session != NULL);

    env = getenv("LIBSSH_VERBOSITY");
    if (env != NULL && strlen(env) >0){
        ssh_options_set(session,SSH_OPTIONS_LOG_VERBOSITY,env);
    }
    rc = ssh_options_set(session,SSH_OPTIONS_HOST,"127.0.0.1");
    assert(rc == 0);
    rc = ssh_options_set(session,SSH_OPTIONS_FD,&socket_fds[0]);
    assert(rc == 0);
    rc = ssh_options_set(session,SSH_OPTIONS_CIPHERS_C_S,"none");
    assert(rc == 0);
    rc = ssh_options_set(session,SSH_OPTIONS_CIPHERS_S_C,"none");
    assert(rc == 0);


    return 0;
}
