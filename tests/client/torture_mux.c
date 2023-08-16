/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#include "torture.h"
#include <libssh/libssh.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <pwd.h>

/* Should work until Apnic decides to assign it :) */
#define BLACKHOLE "1.1.1.1"

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);
    torture_setup_ssh_mux_server();
    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_ssh_mux_server();
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    int control = SSH_CONTROL_MASTER_AUTO;

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, BLACKHOLE);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_CONTROL_MASTER, &control);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_CONTROL_PATH, "..home/alice/.ssh/ssh-%r@%h:%p");

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_connect_mux(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;

    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_connect_mux, session_setup, session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}
