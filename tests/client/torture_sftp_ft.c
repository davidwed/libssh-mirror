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

static void ensure_file_data_equal(const char *name_a, const char *name_b)
{
    struct {
        int fd;
        struct stat attr;
        char *buf;
    } a = {0}, b = {0};

    uint64_t left;
    size_t to_read, chunk_size = 32768;
    ssize_t bytes_read;
    int rc;

    a.buf = malloc(chunk_size);
    assert_non_null(a.buf);

    b.buf = malloc(chunk_size);
    assert_non_null(b.buf);

    a.fd = open(name_a, O_RDONLY, 0);
    assert_int_not_equal(a.fd, -1);

    rc = stat(name_a, &a.attr);
    assert_int_equal(rc, 0);

    b.fd = open(name_b, O_RDONLY, 0);
    assert_int_not_equal(b.fd, -1);

    rc = stat(name_b, &b.attr);
    assert_int_equal(rc, 0);

    /* Ensure that the file sizes are equal */
    assert_int_equal(a.attr.st_size, b.attr.st_size);

    /* Just to be sure that the off_t isn't storing a negative */
    assert_false(a.attr.st_size < 0);

    /* Ensure that the data present in the file is same */
    left = (uint64_t)a.attr.st_size;
    do {
        to_read = MIN(left, chunk_size);

        bytes_read = read(a.fd, a.buf, to_read);
        assert_int_equal(bytes_read, to_read);

        bytes_read = read(b.fd, b.buf, to_read);
        assert_int_equal(bytes_read, to_read);

        assert_memory_equal(a.buf, b.buf, to_read);

        left -= to_read;
    } while (left > 0);

    /* Clean up */
    rc = close(a.fd);
    assert_int_equal(rc, 0);

    rc = close(b.fd);
    assert_int_equal(rc, 0);

    free(a.buf);
    free(b.buf);
}

static void validate_metrics_after_transfer(sftp_ft ft,
                                            uint64_t skip_count,
                                            uint64_t file_size)
{
    uint64_t bytes_transferred, bytes_total, bytes_skipped;

    assert_non_null(ft);

    bytes_transferred = sftp_ft_get_bytes_transferred(ft);
    assert_int_equal(bytes_transferred, file_size);

    bytes_total = sftp_ft_get_bytes_total(ft);
    assert_int_equal(bytes_total, file_size);

    bytes_skipped = sftp_ft_get_bytes_skipped(ft);
    assert_int_equal(bytes_skipped, skip_count);
}

/*
 * This function performs a transfer and then tests whether the transfer was
 * performed correctly or not. The caller should set the transfer type, source
 * path and target path for the transfer before calling this function.
 */
static void test_transfer_ok(sftp_ft ft, int resume_transfer_flag)
{
    int rc;
    const char *source = NULL, *target = NULL;
    uint64_t source_size, skip_count = 0;
    struct stat attr = {0};

    assert_non_null(ft);

    source = sftp_ft_get_source_path(ft);
    assert_non_null(source);

    rc = stat(source, &attr);
    assert_int_equal(rc, 0);
    assert_false(attr.st_size < 0);

    source_size = attr.st_size;

    target = sftp_ft_get_target_path(ft);
    assert_non_null(target);

    if (resume_transfer_flag != 0) {
        /* target file should exist */
        rc = stat(target, &attr);
        assert_int_equal(rc, 0);
        assert_false(attr.st_size < 0);

        skip_count = attr.st_size;
    }

    rc = sftp_ft_options_set(ft,
                             SFTP_FT_OPTIONS_RESUME_TRANSFER,
                             &resume_transfer_flag);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_transfer(ft);
    assert_int_equal(rc, SSH_OK);

    ensure_file_data_equal(source, target);

    validate_metrics_after_transfer(ft, skip_count, source_size);
}

static void set_chunk_size_and_req_count(sftp_ft ft, size_t chunk, size_t req)
{
    int rc;
    assert_non_null(ft);

    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_CHUNK_SIZE, &chunk);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_REQUESTS, &req);
    assert_int_equal(rc, SSH_OK);
}

/*
 * This function performs the transfers using various chunk sizes and request
 * counts. The caller should set the transfer type, source path and target
 * path for the transfer before calling this function.
 */
static void test_chunk_size_and_req_count(sftp_ft ft)
{
    /*
     * OpenSSH sftp server's max sftp packet size or max message length is
     * 256 KB, the server returns a failure if it receives sftp packets of
     * greater length from the client.
     *
     * Also, the max number of bytes that the OpenSSH sftp server can read from
     * a file is 255 KB. This limit was 64 KB for older OpenSSH versions (e.g
     * OpenSSH 8.0) used by some platforms on which libssh's GitLab pipeline
     * runs the tests.
     *
     * libssh sftp client's max sftp packet size is 256 MB, it fails if sftp
     * packets of length greater than 256 MB are received from the server.
     *
     * Considering these limits, the max chunk size to use for uploads/downloads
     * has been kept 64 KB.
     */
    size_t high_chunk_size = 64 * 1024;
    size_t high_req_count = 100;
    size_t low_chunk_size = 10, low_req_count = 1;

    /* Using 0 prompts libssh sftp ft API to use the defaults */
    size_t default_chunk_size = 0, default_req_count = 0;

    struct {
        size_t chunk;
        size_t req;
    } pairs[] = {
        {default_chunk_size, default_req_count},
        {low_chunk_size, default_req_count},
        {high_chunk_size, default_req_count},
        {default_chunk_size, high_req_count},
        {default_chunk_size, low_req_count},
        {low_chunk_size, low_req_count},
        {low_chunk_size, high_req_count},
        {high_chunk_size, low_req_count},
        {high_chunk_size, high_req_count}
    };

    size_t i, pair_count = sizeof(pairs)/sizeof(pairs[0]);

    assert_non_null(ft);

    for (i = 0; i < pair_count; ++i) {
        set_chunk_size_and_req_count(ft, pairs[i].chunk, pairs[i].req);
        test_transfer_ok(ft, 0);
    }
}

static int user_callback(sftp_ft ft)
{
    uint64_t bytes_transferred, bytes_total;

    assert_non_null(ft);

    bytes_transferred = sftp_ft_get_bytes_transferred(ft);
    bytes_total = sftp_ft_get_bytes_total(ft);

    SSH_LOG(SSH_LOG_WARNING, "transferred/total : %"PRIu64"/%"PRIu64"\n",
            bytes_transferred, bytes_total);
    return 0;
}

static void test_sftp_ft_transfer(void **state, enum sftp_ft_type_e type)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_ft ft = s->private_data;

    const char *source = SSH_EXECUTABLE;
    char target[128] = {0};

    struct stat attr = {0};
    uint64_t file_size, partial_size;
    int rc, resume_flag;

    const char *data = "This is a libssh client test for ensuring that the "
                       "sftp ft API performs a file transfer properly";

    snprintf(target, sizeof(target),
             "%s/libssh_sftp_ft_transfer_test", t->testdir);

    rc = stat(source, &attr);
    assert_int_equal(rc, 0);
    assert_false(attr.st_size < 0);

    file_size = attr.st_size;
    partial_size = file_size / 2;

    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TYPE, &type);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_SOURCE_PATH, source);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_TARGET_PATH, target);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_set_pgrs_callback(ft, user_callback, NULL);
    assert_int_equal(rc, SSH_OK);

    test_transfer_ok(ft, 0);

    /* Ensure that the resume transfer feature works correctly */
    rc = truncate(target, partial_size);
    assert_int_equal(rc, 0);

    test_transfer_ok(ft, 1);

    /*
     * Ensure that if the target file already exists with some contents and
     * if the resume transfer option isn't enabled, then the existing contents
     * get truncated before beginning the transfer.
     */
    rc = truncate(target, 0);
    assert_int_equal(rc, 0);

    torture_write_file(target, data);

    test_transfer_ok(ft, 0);

    /*
     * Ensure that if the existing target file's size is greater than the
     * source file's size and if the resume transfer option is enabled, then
     * the transfer fails.
     */
    rc = truncate(target, file_size + 10);
    assert_int_equal(rc, 0);

    resume_flag = 1;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_RESUME_TRANSFER, &resume_flag);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_transfer(ft);
    assert_int_equal(rc, SSH_ERROR);

    /* Perform transfers using various chunk sizes and request counts. */
    test_chunk_size_and_req_count(ft);

    /* Delete the target file */
    rc = unlink(target);
    assert_int_not_equal(rc, -1);

    /*
     * Ensure the the transfer fails when the target file doesn't exist and the
     * transfer is tried to be resumed.
     */
    resume_flag = 1;
    rc = sftp_ft_options_set(ft, SFTP_FT_OPTIONS_RESUME_TRANSFER, &resume_flag);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_ft_transfer(ft);
    assert_int_equal(rc, SSH_ERROR);
}

static void torture_sftp_ft_upload(void **state)
{
    enum sftp_ft_type_e type = SFTP_FT_TYPE_UPLOAD;
    test_sftp_ft_transfer(state, type);
}

static void torture_sftp_ft_download(void **state)
{
    enum sftp_ft_type_e type = SFTP_FT_TYPE_DOWNLOAD;
    test_sftp_ft_transfer(state, type);
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
        cmocka_unit_test_setup_teardown(torture_sftp_ft_upload,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_sftp_ft_download,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
