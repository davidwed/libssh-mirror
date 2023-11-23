#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static void torture_no_more_sessions(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_channel extra_channel = NULL;
    int rc;

    /* Make sure we can't open a channel after doing a no more sessions request */
    do {
        rc = ssh_request_no_more_sessions(session);
    } while (rc == SSH_AGAIN);
    assert_ssh_return_code(session, rc);
    extra_channel = ssh_channel_new(session);
    assert_non_null(extra_channel);
    do {
        rc = ssh_channel_open_session(extra_channel);
    } while (rc == SSH_AGAIN);
    assert_int_equal(rc, SSH_ERROR);
    ssh_channel_free(extra_channel);
}

static void session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd;
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

    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);
}

static void session_setup_channel(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    ssh_channel c = NULL;
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

    c = ssh_channel_new(s->ssh.session);
    assert_non_null(c);

    s->ssh.tsftp = torture_sftp_session_channel(s->ssh.session, c);
    assert_non_null(s->ssh.tsftp);

    torture_no_more_sessions(state);
}

static ssh_session torture_create_nonblocking_ssh_client_session(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    ssh_session session = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    session = ssh_new();
    assert_non_null(s->ssh.session);
    s->ssh.session = session;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);

    rc = ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);
    assert_ssh_return_code(session, rc);

    ssh_set_blocking(session,0);
    do {
        rc = ssh_connect(session);
        assert_ssh_return_code_not_equal(session, rc, SSH_ERROR);
    } while(rc == SSH_AGAIN);

    do {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    } while (rc == SSH_AUTH_AGAIN);
    assert_ssh_return_code_equal(session, rc, SSH_AUTH_SUCCESS);

    return session;
}

static void session_setup_nonblocking(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = NULL;
    struct torture_sftp *t;
    int rc;

    session = torture_create_nonblocking_ssh_client_session(state);
    t = malloc(sizeof(struct torture_sftp));
    assert_non_null(t);
    s->ssh.tsftp = t;

    t->sftp = sftp_new2(session);
    assert_non_null(t->sftp);
    assert_non_null(t->sftp->session);
    assert_null(t->sftp->channel);

    do {
        rc = sftp_init2(t->sftp, NULL);
        assert_ssh_return_code_not_equal(session, rc, SSH_ERROR);
    } while (rc == SSH_AGAIN);

    assert_non_null(t->sftp->channel);

    t->testdir = NULL;

    torture_no_more_sessions(state);
}

static void session_setup_nonblocking_channel(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = NULL;
    ssh_channel channel = NULL;
    struct torture_sftp *t;
    int rc;

    session = torture_create_nonblocking_ssh_client_session(state);
    t = malloc(sizeof(struct torture_sftp));
    assert_non_null(t);
    s->ssh.tsftp = t;

    t->sftp = sftp_new2(session);
    assert_non_null(t->sftp);
    assert_non_null(t->sftp->session);
    assert_null(t->sftp->channel);

    channel = ssh_channel_new(s->ssh.session);
    assert_non_null(channel);

    do {
        rc = sftp_init2(t->sftp, channel);
        assert_ssh_return_code_not_equal(session, rc, SSH_ERROR);
    } while (rc == SSH_AGAIN);

    assert_non_null(t->sftp->channel);

    t->testdir = NULL;

    torture_no_more_sessions(state);
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);
    return 0;
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(session_setup,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(session_setup_channel,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(session_setup_nonblocking,
                                        NULL,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(session_setup_nonblocking_channel,
                                        NULL,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
