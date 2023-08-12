#define LIBSSH_STATIC

#include "config.h"

#include "torture.h"
#include "sftp.c"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);
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
    struct passwd *pwd = NULL;
    sftp_ft ft = NULL;
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

    ft = sftp_ft_new(s->ssh.tsftp->sftp);
    assert_non_null(ft);

    s->private_data = ft;

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;

    sftp_ft_free(ft);
    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_ft_options_set(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    int rc;

    /* Negative test */

    /* Invalid option type */
    rc = sftp_ft_options_set(ft, 1000, NULL);
    assert_int_equal(rc, SSH_ERROR);
}

/* Test the setting of the chunk size */
static void torture_ft_options_set_chunk(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    size_t chunk;
    int rc;

    /* Test that the normal usage works as intended */
    chunk = 20;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_CHUNK_SIZE, &chunk);
    assert_int_equal(rc, SSH_OK);

    chunk = sftp_ft_get_chunk_size(ft);
    assert_int_equal(chunk, 20);

    /* Test that the using 0 is allowed to revert to default */
    chunk = 0;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_CHUNK_SIZE, &chunk);
    assert_int_equal(rc, SSH_OK);

    chunk = sftp_ft_get_chunk_size(ft);
    assert_int_equal(chunk, 0);

    /* Negative tests */
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_CHUNK_SIZE, NULL);
    assert_int_equal(rc, SSH_ERROR);

    chunk = 20;
    rc = sftp_ft_options_set(NULL, SFTP_FT_OPTIONS_CHUNK_SIZE, &chunk);
    assert_int_equal(rc, SSH_ERROR);
}

/* Test the settings of the requests count */
static void torture_ft_options_set_requests(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    size_t requests;
    int rc;

    /* Test that the normal usage works as intended */
    requests = 5;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_REQUESTS, &requests);
    assert_int_equal(rc, SSH_OK);

    requests = sftp_ft_get_requests_count(ft);
    assert_int_equal(requests, 5);

    /* Test that using 0 reverts to the default (20 as per doc) */
    requests = 0;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_REQUESTS, &requests);
    assert_int_equal(rc, SSH_OK);

    requests = sftp_ft_get_requests_count(ft);
    assert_int_equal(requests, 20);

    /* Negative tests */
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_REQUESTS, NULL);
    assert_int_equal(rc, SSH_ERROR);

    requests = 5;
    rc = sftp_ft_options_set(NULL, SFTP_FT_OPTIONS_REQUESTS, &requests);
    assert_int_equal(rc, SSH_ERROR);
}

/* Test the setting of the source path */
static void torture_ft_options_set_source(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    const char *source = "libssh_sftp_ft_options_source";
    const char *path = NULL;
    int rc;

    /* Test that the normal usage works as intended */
    path = source;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_SOURCE_PATH, path);
    assert_int_equal(rc, SSH_OK);

    path = sftp_ft_get_source_path(ft);
    assert_string_equal(path, source);

    /* Negative tests */
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_SOURCE_PATH, NULL);
    assert_int_equal(rc, SSH_ERROR);

    rc = sftp_ft_options_set(NULL, SFTP_FT_OPTIONS_SOURCE_PATH, source);
    assert_int_equal(rc, SSH_ERROR);
}

/* Test the setting of the target path */
static void torture_ft_options_set_target(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    const char *target = "libssh_sftp_ft_options_target";
    const char *path = NULL;
    int rc;

    /* Test that the normal usage works as intended */
    path = target;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TARGET_PATH, path);
    assert_int_equal(rc, SSH_OK);

    path = sftp_ft_get_target_path(ft);
    assert_string_equal(path, target);

    /* Negative tests */
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TARGET_PATH, NULL);
    assert_int_equal(rc, SSH_ERROR);

    rc = sftp_ft_options_set(NULL, SFTP_FT_OPTIONS_TARGET_PATH, target);
    assert_int_equal(rc, SSH_ERROR);
}

/* Test the setting of the transfer type */
static void torture_ft_options_set_type(void **state)
{
    struct torture_state *s = *state;
    sftp_ft ft = s->private_data;
    enum sftp_ft_type_e type;
    int rc;

    type = SFTP_FT_TYPE_UPLOAD;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_OK);

    type = SFTP_FT_TYPE_DOWNLOAD;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_OK);

    type = SFTP_FT_TYPE_REMOTE_COPY;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_OK);

    /* Negative tests */

    /* Local copy transfers aren't currently supported by libssh */
    type = SFTP_FT_TYPE_LOCAL_COPY;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_ERROR);

    /* Invalid transfer type */
    type = 100;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_ERROR);

    rc = sftp_ft_options_set(NULL, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_ERROR);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_ft_options_set,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ft_options_set_chunk,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ft_options_set_requests,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ft_options_set_source,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ft_options_set_target,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ft_options_set_type,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
