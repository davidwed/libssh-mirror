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
#include <sys/statvfs.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define LIBSSH_STATIC 1
#define BUF_SIZE 65536

#include "libssh/sftp.h"
#include "libssh/libssh.h"

// ideally fuzz would contain two parts
// 1. Setup of fuzzer
// 2. loop of fuzz

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    ssh_session session;
    int nwritten;
    char *env;
    int socket_fds[2] = {-1,1};
    sftp_session sftp = sftp_new(session);
    sftp_dir dir;
    sftp_attributes file;
    sftp_statvfs_t sftpstatvfs;
    struct statvfs sysstatvfs;
    sftp_file source;
    sftp_file to;
    int len = 1;
    unsigned int i;
    char temp[BUF_SIZE] = {0};
    char *lnk = NULL;
    int rc;
    int count;
    long timeout = 1;

    if (size > 219264) {
        return -1;
    }

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
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, "none");
    assert(rc == 0);
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "none");
    assert(rc == 0);

    rc = ssh_connect(session);
    if (rc != SSH_OK){
        goto end;
    }

    rc = ssh_userauth_none(session,NULL);
    if (rc != SSH_OK){
        goto end;
    }

    if (sftp_init(sftp))
    {
        goto end;
    }

    count = sftp_extensions_get_count(sftp);
    if (!count){
        goto end;
    }
    for (i = 0; i < count; i++)
    {
        if (sftp_extensions_get_name(sftp, i) == NULL){
            goto end;
        }
        if (sftp_extensions_get_data(sftp, i) == NULL){
            goto end;
        }
    }

    /* test symlink and readlink */
    if (sftp_symlink(sftp, "/tmp/this_is_the_link",
                     "/tmp/sftp_symlink_test") < 0)
    {
        goto end;
    }

    lnk = sftp_readlink(sftp, "/tmp/sftp_symlink_test");
    if (lnk == NULL)
    {
        goto end;
    }

    ssh_string_free_char(lnk);

    if (sftp_unlink(sftp, "/tmp/sftp_symlink_test") < 0){
        goto end;
    }

    if (sftp_extension_supported(sftp, "statvfs@openssh.com", "2"))
    {
        sftpstatvfs = sftp_statvfs(sftp, "/tmp");
        if (sftpstatvfs == NULL)
        {
            goto end;
        }

        sftp_statvfs_free(sftpstatvfs);

        if (statvfs("/tmp", &sysstatvfs) < 0)
        {
            goto end;
        }
    }

    dir = sftp_opendir(sftp, "./");
    if (!dir)
    {
        goto end;
    }

    file = sftp_readdir(sftp, dir);
    if (file == NULL){
        goto end;
    }

    sftp_attributes_free(file);

    if (!sftp_dir_eof(dir))
    {
        goto end;
    }

    if (sftp_closedir(dir))
    {
        goto end;
    }

    source = sftp_open(sftp, "/usr/bin/ssh", O_RDONLY, 0);
    if (!source)
    {
        goto end;
    }

    to = sftp_open(sftp, "ssh-copy", O_WRONLY | O_CREAT, 0700);
    if (!to)
    {
        goto end;
    }

    while ((len = sftp_read(source, temp, 4096)) > 0)
    {
        if (sftp_write(to, temp, len) != len)
        {
            goto end;
        }
    }

    if (len < 0)
    {
        goto end;
    }

    sftp_close(source);
    sftp_close(to);

    to = sftp_open(sftp, "/tmp/large_file", O_WRONLY | O_CREAT, 0644);

    len = sftp_write(to, temp, sizeof(temp));
    if (len != sizeof(temp))
    {
        goto end;
    }

    end:
    sftp_close(source);
    sftp_close(to);
    sftp_close(source);
    sftp_free(sftp);

    ssh_disconnect(session);
    ssh_free(session);
    free(env);

    ssh_finalize();

    close(socket_fds[0]);
    close(socket_fds[1]);

    return 0;
}
