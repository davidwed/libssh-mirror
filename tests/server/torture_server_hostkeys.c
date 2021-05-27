/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

#define LIBSSH_STATIC

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>

#include "torture.h"
#include "torture_key.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/token.h"

#include "test_server.h"
#include "default_cb.h"

const char template[] = "temp_dir_XXXXXX";

struct test_server_st {
    struct torture_state *state;
    char *cwd;
    char *temp_dir;
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
};

static int setup_files(void **state)
{
    struct test_server_st *tss;
    struct torture_state *s;
    char sshd_path[1024];

    int rc;

    tss = (struct test_server_st*)calloc(1, sizeof(struct test_server_st));
    assert_non_null(tss);

    torture_setup_socket_dir((void **)&s);
    assert_non_null(s->socket_dir);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(tss->rsa_hostkey,
             sizeof(tss->rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(tss->rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0));

    snprintf(tss->ecdsa_hostkey,
             sizeof(tss->ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(tss->ecdsa_hostkey, torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0));

    tss->state = s;
    *state = tss;

    return 0;
}

static int teardown_files(void **state)
{
    struct torture_state *s;
    struct test_server_st *tss;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    torture_teardown_socket_dir((void **)&s);
    SAFE_FREE(tss);

    return 0;
}

static int setup_temp_dir(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    char *cwd = NULL;
    char *tmp_dir = NULL;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tmp_dir = torture_make_temp_dir(template);
    assert_non_null(tmp_dir);

    tss->cwd = cwd;
    tss->temp_dir = tmp_dir;

    return 0;
}

static int teardown_temp_dir(void **state)
{
    struct test_server_st *tss = *state;
    int rc;

    assert_non_null(tss);

    rc = torture_change_dir(tss->cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(tss->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(tss->temp_dir);
    SAFE_FREE(tss->cwd);

    return 0;
}

static int start_server(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    /* Start the server using the default values */
    torture_setup_libssh_server((void **)&s, "./test_server/test_server");
    assert_non_null(s);

    return 0;
}

static int stop_server(void **state)
{
    struct torture_state *s;
    struct test_server_st *tss;

    int rc;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    rc = torture_terminate_process(s->srv_pidfile);
    assert_return_code(rc, errno);

    unlink(s->srv_pidfile);

    return 0;
}

static int session_setup(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool b = false;
    int rc;

    assert_non_null(tss);

    /* Make sure we do not test the agent */
    unsetenv("SSH_AUTH_SOCK");

    s = tss->state;
    assert_non_null(s);

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);
    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_server_hostkeys(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    char config_content[4096];

    ssh_session session = NULL;
    ssh_channel channel = NULL;

    int rc;

    assert_non_null(tss);
    s = tss->state;
    assert_non_null(s);

    /* Prepare key files */
    snprintf(config_content,
             sizeof(config_content),
             "HostKey %s\nHostKey %s\n",
             tss->rsa_hostkey,
             tss->ecdsa_hostkey);

    assert_non_null(s->srv_config);
    torture_write_file(s->srv_config, config_content);

    fprintf(stderr, "Config file %s content: \n\n%s\n", s->srv_config,
            config_content);
    fflush(stderr);

    /* Start server */
    rc = start_server(state);
    assert_int_equal(rc, 0);

    /* Setup session */
    rc = session_setup(state);
    assert_int_equal(rc, 0);

    session = s->ssh.session;
    assert_non_null(session);

    /* Authenticate as alice with bob's pubkey */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    rc = ssh_message_request_hostkeys_prove(session, 1000);
    assert_ssh_return_code(session, rc);

    assert_non_null(session->opts.verified_host_keys);

    /* Open channel to make sure the session is working */
    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_ssh_return_code(session, rc);

    ssh_channel_close(channel);

    rc = session_teardown(state);
    assert_int_equal(rc, 0);

    rc = stop_server(state);
    assert_int_equal(rc, 0);

    SAFE_FREE(s->srv_additional_config);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_server_hostkeys,
                                        setup_temp_dir, teardown_temp_dir),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
                                setup_files,
                                teardown_files);

    ssh_finalize();

    return rc;
}
