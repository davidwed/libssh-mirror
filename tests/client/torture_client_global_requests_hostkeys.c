/*
 * torture_client_global_requests_hostkeys.c - Tests hostkeys global requests
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
 * Author: Dirkjan Bussink <d.bussink@gmail.com>
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
#define TMP_FILE_TEMPLATE "known_hosts_XXXXXX"

#include "torture.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/channels.h"
#include "libssh/knownhosts.h"

#include <errno.h>
#include <sys/types.h>
#include <pwd.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, true);

    return 0;
}

static int sshd_teardown(void **state)
{
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool b = false;
    int rc;
    char hostkeys[] = "rsa-sha2-256,ecdsa-sha2-nistp256";

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOSTKEYS, &hostkeys);
    assert_ssh_return_code(s->ssh.session, rc);
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
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static int authenticate(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_BOB);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_password(session, NULL, TORTURE_SSH_USER_BOB_PASSWORD);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    return rc;
}

static void torture_global_request_hostkeys(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    struct ssh_iterator *it = NULL;
    ssh_key key = NULL;
    ssh_key ecdsa_key = NULL;
    ssh_key rsa_key = NULL;
    char tmp_file[1024] = {0};
    char *known_hosts_file = NULL;
    enum ssh_known_hosts_e status = SSH_KNOWN_HOSTS_ERROR;
    ssh_channel channel = NULL;
    int rc;

    snprintf(tmp_file,
             sizeof(tmp_file),
             "%s/%s",
             s->socket_dir,
             TMP_FILE_TEMPLATE);

    known_hosts_file = torture_create_temp_file(tmp_file);
    assert_non_null(known_hosts_file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    rc = authenticate(state);
    assert_ssh_return_code(session, rc);

    assert_null(session->opts.verified_host_keys);

    rc = ssh_message_request_hostkeys_prove(session, SSH_TIMEOUT_INFINITE);
    assert_ssh_return_code(session, rc);

    assert_non_null(session->opts.verified_host_keys);
    assert_true(ssh_list_count(session->opts.verified_host_keys) > 0);

    /* RSA is configured for the client, so we want to
     * see at least the ECDSA host key here.*/
    for (it = ssh_list_get_iterator(session->opts.verified_host_keys); it != NULL; it = it->next) {
        key = (ssh_key) it->data;
        switch(ssh_key_type(key)) {
        case SSH_KEYTYPE_RSA:
            rsa_key = key;
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            ecdsa_key = key;
            break;
        default:
            break;
        }
    }

    /* The RSA key is already used so is not in this list */
    assert_null(rsa_key);
    assert_non_null(ecdsa_key);

    rc = ssh_session_update_known_hosts(session);
    assert_ssh_return_code(session, rc);

    status = ssh_session_is_known_server(session);
    assert_int_equal(status, SSH_KNOWN_HOSTS_OK);

    status = ssh_session_known_hosts_entry_exists(session, ecdsa_key);
    assert_int_equal(status, SSH_KNOWN_HOSTS_OK);

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);

    assert_ssh_return_code(session, rc);

    ssh_channel_close(channel);

    free(known_hosts_file);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_global_request_hostkeys,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
