/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2024 by Red Hat, Inc.
 *
 * Authors: Jakub Jelen <jjelen@redhat.com>
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
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <pwd.h>

#include "connector.c"

#define ROUNDS 100000
/* Simple writer service writes consecutive numbers up to 100k and then "end" */
#define WRITER_SERVICE \
    "N=0; while [ $N -lt 100000 ]; do N=$((N+1)); echo \"$N\"; done; echo end"
#define WRITER_STDERR_SERVICE \
    "N=0;while [ $N -lt 100000 ];do N=$((N+1));echo \"$N\" >&2;done;echo end"
/* Simple echo service which repeats what is written in until "end" input */
#define ECHO_SERVICE "while [ \"$V\" != \"end\" ]; do read V; echo \"$V\"; done"
/* Simple sink service which reads the whole input until "end" is received */
#define SINK_SERVICE "while [ \"$V\" != \"end\" ]; do read V; done"

static int
sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int
sshd_teardown(void **state)
{
    torture_teardown_sshd_server(state);

    return 0;
}

static int
session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    return 0;
}

static int
session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

/* Open a channel and execute the given command in the given session */
static ssh_channel
torture_channel_setup(ssh_session session, const char *command)
{
    int rc;
    ssh_channel channel = NULL;

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_ssh_return_code(session, rc);

    rc = ssh_channel_request_exec(channel, command);
    assert_ssh_return_code(session, rc);

    return channel;
}

static ssh_connector
connector_from_fd_to_channel(int fd,
                             ssh_channel channel,
                             enum ssh_connector_flags_e channel_flags)
{
    ssh_connector connector = NULL;
    ssh_session session = NULL;
    int rc;

    session = ssh_channel_get_session(channel);
    assert_non_null(session);

    connector = ssh_connector_new(session);
    assert_non_null(connector);

    ssh_connector_set_in_fd(connector, fd);

    rc = ssh_connector_set_out_channel(connector, channel, channel_flags);
    assert_ssh_return_code(session, rc);

    return connector;
}

static ssh_connector
connector_from_channel_to_fd(ssh_channel channel,
                             enum ssh_connector_flags_e channel_flags,
                             int fd)
{
    ssh_connector connector = NULL;
    ssh_session session = NULL;
    int rc;

    session = ssh_channel_get_session(channel);
    assert_non_null(session);

    connector = ssh_connector_new(session);
    assert_non_null(connector);

    rc = ssh_connector_set_in_channel(connector, channel, channel_flags);
    assert_ssh_return_code(session, rc);

    ssh_connector_set_out_fd(connector, fd);

    return connector;
}

static ssh_connector
connector_from_channel_to_channel(ssh_channel channel_from,
                                  enum ssh_connector_flags_e channel_from_flags,
                                  ssh_channel channel_to,
                                  enum ssh_connector_flags_e channel_to_flags)
{
    ssh_connector connector = NULL;
    ssh_session session = NULL;
    int rc;

    session = ssh_channel_get_session(channel_from);
    assert_non_null(session);

    /* The channel can not operate cross-session */
    assert_ptr_equal(session, ssh_channel_get_session(channel_to));

    connector = ssh_connector_new(session);
    assert_non_null(connector);

    rc = ssh_connector_set_in_channel(connector,
                                      channel_from,
                                      channel_from_flags);
    assert_ssh_return_code(session, rc);

    rc = ssh_connector_set_out_channel(connector, channel_to, channel_to_flags);
    assert_ssh_return_code(session, rc);

    return connector;
}

/*
 * Basic and most common test of redirecting the channel to local FD and vice
 * versa (FD to channel). This tests writes into pipe, which is redirected as an
 * input to the remote command, which repeats the input and another connector
 * writes to /dev/null. Stderr of channel is redirected to stderr of the
 * program.
 */
static void
torture_connector_io(void **state)
{
    char buf[100];
    size_t buf_len = 100;
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_in = NULL, connector_out = NULL;
    ssh_connector connector_err = NULL;
    int pipefd[2];
    ssh_event event = NULL;
    ssh_channel channel = NULL;
    int rc, devnull;
    int i = 0;

    channel = torture_channel_setup(session, ECHO_SERVICE);
    assert_non_null(channel);

    rc = pipe(pipefd);
    assert_int_equal(rc, 0);

    devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    event = ssh_event_new();
    assert_non_null(event);

    /* pipe -> remote stdin */
    connector_in = connector_from_fd_to_channel(pipefd[0],
                                                channel,
                                                SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_in);
    ssh_event_add_connector(event, connector_in);

    /* remote stdout -> /dev/null */
    connector_out = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDINOUT,
                                                 devnull);
    assert_non_null(connector_out);
    ssh_event_add_connector(event, connector_out);

    /* remote stderr -> stderr */
    connector_err = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDERR,
                                                 STDERR_FILENO);
    assert_non_null(connector_err);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        if (i < ROUNDS) {
            snprintf(buf, sizeof(buf), "%d\n", i++);
        } else {
            snprintf(buf, sizeof(buf), "end\n");
        }
        buf_len = strlen(buf);
        rc = write(pipefd[1], buf, buf_len);
        assert_int_equal(rc, buf_len);

        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);

    ssh_channel_free(channel);

    close(devnull);
    close(pipefd[0]);
    close(pipefd[1]);
}

/*
 * This test is similar, but probes just one direction of the channel --
 * writing. Remote program eats whole input and stays quiet.
 */
static void
torture_connector_writes(void **state)
{
    char buf[100];
    size_t buf_len = 100;
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_in = NULL, connector_out = NULL;
    ssh_connector connector_err = NULL;
    int pipefd[2];
    ssh_event event = NULL;
    ssh_channel channel = NULL;
    int rc;
    int i = 0;

    channel = torture_channel_setup(session, SINK_SERVICE);
    assert_non_null(channel);

    event = ssh_event_new();
    assert_non_null(event);

    rc = pipe(pipefd);
    assert_int_equal(rc, 0);

    /* pipe -> remote stdin */
    connector_in = connector_from_fd_to_channel(pipefd[0],
                                                channel,
                                                SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_in);
    ssh_event_add_connector(event, connector_in);

    /* remote stdout -> stdout */
    connector_out = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDINOUT,
                                                 STDOUT_FILENO);
    assert_non_null(connector_out);
    ssh_event_add_connector(event, connector_out);

    /* remote stderr -> stderr */
    connector_err = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDERR,
                                                 STDERR_FILENO);
    assert_non_null(connector_err);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        if (i < ROUNDS) {
            snprintf(buf, sizeof(buf), "%d\n", i++);
        } else {
            snprintf(buf, sizeof(buf), "end\n");
        }
        buf_len = strlen(buf);
        rc = write(pipefd[1], buf, buf_len);
        assert_int_equal(rc, buf_len);

        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);

    ssh_channel_free(channel);

    close(pipefd[0]);
    close(pipefd[1]);
}

/*
 * This test is similar, but probes just one direction of the channel --
 * reading. Remote program generates some output that is locally redirected to
 * /dev/null.
 */
static void
torture_connector_reads(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_in = NULL, connector_out = NULL;
    ssh_connector connector_err = NULL;
    ssh_event event = NULL;
    ssh_channel channel = NULL;
    int rc, devnull;

    channel = torture_channel_setup(session, WRITER_SERVICE);
    assert_non_null(channel);

    event = ssh_event_new();
    assert_non_null(event);

    devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    /* /dev/null -> remote stdin */
    connector_in = connector_from_fd_to_channel(devnull,
                                                channel,
                                                SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_in);
    ssh_event_add_connector(event, connector_in);

    /* remote stdout -> /dev/null */
    connector_out = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDINOUT,
                                                 devnull);
    assert_non_null(connector_out);
    ssh_event_add_connector(event, connector_out);

    /* remote stderr -> stderr */
    connector_err = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDERR,
                                                 STDERR_FILENO);
    assert_non_null(connector_err);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);

    ssh_channel_free(channel);

    close(devnull);
}

/*
 * This tests probes the default connector flags fallback that it makes sense
 * and keep working.
 */
static void
torture_connector_default_flags(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_in = NULL, connector_out = NULL;
    ssh_connector connector_err = NULL;
    ssh_event event = NULL;
    ssh_channel channel = NULL;
    int rc, devnull;

    channel = torture_channel_setup(session, WRITER_SERVICE);
    assert_non_null(channel);

    event = ssh_event_new();
    assert_non_null(event);

    devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    /* /dev/null -> remote stdin */
    connector_in = connector_from_fd_to_channel(devnull, channel, 0);
    assert_non_null(connector_in);
    /* with 0 it should default to SSH_CONNECTOR_STDINOUT */
    assert_int_equal(connector_in->out_flags, SSH_CONNECTOR_STDINOUT);
    ssh_event_add_connector(event, connector_in);

    /* remote stdout -> /dev/null */
    connector_out = connector_from_channel_to_fd(channel, 0, devnull);
    assert_non_null(connector_out);
    /* with 0 it should default to SSH_CONNECTOR_STDINOUT */
    assert_int_equal(connector_out->in_flags, SSH_CONNECTOR_STDINOUT);
    ssh_event_add_connector(event, connector_out);

    /* remote stderr -> stderr */
    connector_err = connector_from_channel_to_fd(channel,
                                                 SSH_CONNECTOR_STDERR,
                                                 STDERR_FILENO);
    assert_non_null(connector_err);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);

    ssh_channel_free(channel);

    close(devnull);
}

static void
torture_connector_channels(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_one = NULL, connector_two = NULL;
    ssh_event event = NULL;
    ssh_channel channel = NULL, channel2 = NULL;
    int rc, devnull;

    channel = torture_channel_setup(session, WRITER_SERVICE);
    assert_non_null(channel);

    channel2 = torture_channel_setup(session, ECHO_SERVICE);
    assert_non_null(channel2);

    /*
     * handle the IO between these two using connector directing the output of
     * first channel to the second one. From there we will dump it to /dev/null
     */
    event = ssh_event_new();
    assert_non_null(event);

    devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    /* channel1 stdout -> channel2 stdin */
    connector_one = connector_from_channel_to_channel(channel,
                                                      SSH_CONNECTOR_STDINOUT,
                                                      channel2,
                                                      SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_one);
    ssh_event_add_connector(event, connector_one);

    /* channel2 stdout -> /dev/null */
    connector_two = connector_from_channel_to_fd(channel2,
                                                 SSH_CONNECTOR_STDINOUT,
                                                 devnull);
    assert_non_null(connector_two);
    ssh_event_add_connector(event, connector_two);

    while (ssh_channel_is_open(channel) && ssh_channel_is_open(channel2)) {
        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_one);
    ssh_event_remove_connector(event, connector_two);

    ssh_connector_free(connector_one);
    ssh_connector_free(connector_two);

    ssh_event_free(event);

    ssh_channel_free(channel);
    ssh_channel_free(channel2);

    close(devnull);
}

static void
torture_connector_channels_stderr(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_connector connector_one = NULL, connector_two = NULL;
    ssh_connector connector_stderr = NULL;
    ssh_event event;
    ssh_channel channel, channel2;
    int rc, devnull;

    channel = torture_channel_setup(session, WRITER_STDERR_SERVICE);
    assert_non_null(channel);

    channel2 = torture_channel_setup(session, ECHO_SERVICE);
    assert_non_null(channel2);

    /*
     * handle the IO between these two using connector directing the output of
     * first channel to the second one. From there we will dump it into
     * /dev/null
     */
    event = ssh_event_new();
    assert_non_null(event);

    devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    /* channel1 stdout -> channel2 stdin */
    connector_one = connector_from_channel_to_channel(channel,
                                                      SSH_CONNECTOR_STDINOUT,
                                                      channel2,
                                                      SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_one);
    ssh_event_add_connector(event, connector_one);

    /* channel1 stderr -> channel2 stdin */
    connector_stderr = connector_from_channel_to_channel(channel,
                                                         SSH_CONNECTOR_STDERR,
                                                         channel2,
                                                         SSH_CONNECTOR_STDINOUT);
    assert_non_null(connector_stderr);
    ssh_event_add_connector(event, connector_one);

    /* channel2 stdout -> /dev/null */
    connector_two = connector_from_channel_to_fd(channel2,
                                                 SSH_CONNECTOR_STDINOUT,
                                                 devnull);
    assert_non_null(connector_two);
    ssh_event_add_connector(event, connector_two);

    while (ssh_channel_is_open(channel) && ssh_channel_is_open(channel2)) {
        rc = ssh_event_dopoll(event, 60000);
        assert_int_not_equal(rc, SSH_ERROR);
    }
    ssh_event_remove_connector(event, connector_one);
    ssh_event_remove_connector(event, connector_two);
    ssh_event_remove_connector(event, connector_stderr);

    ssh_connector_free(connector_one);
    ssh_connector_free(connector_two);
    ssh_connector_free(connector_stderr);

    ssh_event_free(event);

    ssh_channel_free(channel);
    ssh_channel_free(channel2);

    close(devnull);
}

int
torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_connector_io,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_connector_writes,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_connector_reads,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_connector_default_flags,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_connector_channels,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_connector_channels_stderr,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}
