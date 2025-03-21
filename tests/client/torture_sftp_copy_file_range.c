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

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    torture_rmdirs(s->ssh.tsftp->testdir);
    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void get_sftp_file_offsets(sftp_file file_in, uint64_t *off_in,
                                  sftp_file file_out, uint64_t *off_out)
{
    assert_non_null(file_in);
    assert_non_null(off_in);
    assert_non_null(file_out);
    assert_non_null(off_out);

    *off_in = sftp_tell(file_in);
    *off_out = sftp_tell(file_out);
}

static void set_sftp_file_offsets(sftp_file file_in, uint64_t off_in,
                                  sftp_file file_out, uint64_t off_out)
{
    int rc;

    assert_non_null(file_in);
    assert_non_null(file_out);

    rc = sftp_seek64(file_in, off_in);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_seek64(file_out, off_out);
    assert_int_equal(rc, SSH_OK);
}

/*
 * Validates that len bytes starting from file offset off_out in fd_out
 * are same as the len bytes present in the buffer pointed by buf.
 */
static void validate_data(int fd_out, uint64_t off_out,
                          const void *buf, size_t len)
{
    uint64_t left = off_out;
    off_t off, to_seek;
    ssize_t bytes_read;
    char *read_buf = NULL;

    read_buf = malloc(sizeof(char) * len);
    assert_non_null(read_buf);

    /* Set the file offset to 0 initially */
    off = lseek(fd_out, 0, SEEK_SET);
    assert_int_not_equal(off, -1);

    /*
     * Loop to avoid the overflow that can be caused due to the implicit
     * uint64_t -> off_t conversion if off_out is passed to lseek() directly
     */
    do {
        to_seek = (left > INT32_MAX ? INT32_MAX : left);
        off = lseek(fd_out, to_seek, SEEK_CUR);
        assert_int_not_equal(off, -1);

        left -= (uint64_t)to_seek;
    } while (left > 0);

    bytes_read = read(fd_out, read_buf, len);
    assert_int_equal(bytes_read, len);

    assert_memory_equal(read_buf, buf, len);

    free(read_buf);
}

static void torture_sftp_copy_file_range(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    sftp_session tmp_sftp = NULL;

    char file_in_name[128] = {0}, file_out_name[128] = {0};

    sftp_file file_in = NULL, file_out = NULL;
    int fd_out;

    const char *data = "This is a client test to test sftp_copy_file_range() "
                       "present in the SFTP API. This function adds support "
                       "for the copy-data extension.";

    const uint64_t off_rd = 2, off_wr = 10, len = strlen(data) - off_rd - 1;
    uint64_t off_in, off_out;
    int64_t len_copy;
    int rc;

    /* Perform the test only when the "copy-data" extension is supported */
    rc = sftp_extension_supported(t->sftp, "copy-data", "1");
    if (rc == 0) {
        skip();
    }

    snprintf(file_in_name, sizeof(file_in_name),
             "%s/libssh_sftp_copy_file_range_test_file_in", t->testdir);
    snprintf(file_out_name, sizeof(file_out_name),
             "%s/libssh_sftp_copy_file_range_test_file_out", t->testdir);

    torture_write_file(file_in_name, data);

    file_in = sftp_open(t->sftp, file_in_name, O_RDONLY, 0);
    assert_non_null(file_in);

    file_out = sftp_open(t->sftp, file_out_name, O_WRONLY | O_CREAT, 0777);
    assert_non_null(file_out);

    fd_out = open(file_out_name, O_RDONLY, 0);
    assert_int_not_equal(fd_out, -1);

    /* Try copying using the file offsets */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);

    len_copy = sftp_copy_file_range(file_in, NULL, file_out, NULL, len);
    assert_int_equal(len_copy, len);

    /* Ensure that the file offsets got updated correctly */
    get_sftp_file_offsets(file_in, &off_in, file_out, &off_out);
    assert_int_equal(off_in, off_rd + len);
    assert_int_equal(off_out, off_wr + len);

    validate_data(fd_out, off_wr, data + off_rd, len);

    /* Try copying using the offsets present in the supplied buffers */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    off_in = off_rd;
    off_out = off_wr;

    len_copy = sftp_copy_file_range(file_in, &off_in, file_out, &off_out, len);
    assert_int_equal(len_copy, len);

    /* Ensure that the offsets got updated correctly in the supplied buffers */
    assert_int_equal(off_in, off_rd + len);
    assert_int_equal(off_out, off_wr + len);

    /* Ensure that the file offsets did not get updated */
    get_sftp_file_offsets(file_in, &off_in, file_out, &off_out);
    assert_int_equal(off_in, off_rd);
    assert_int_equal(off_out, off_wr);

    validate_data(fd_out, off_wr, data + off_rd, len);

    /*
     * Try copying using the file offset for file_in and an offset present in
     * a buffer for file_out.
     */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    off_out = off_wr;

    len_copy = sftp_copy_file_range(file_in, NULL, file_out, &off_out, len);
    assert_int_equal(len_copy, len);

    /* Ensure that the offset got updated correctly in the supplied buffer */
    assert_int_equal(off_out, off_wr + len);

    /* Ensure that file_in's offset got updated but file_out's didn't */
    get_sftp_file_offsets(file_in, &off_in, file_out, &off_out);
    assert_int_equal(off_in, off_rd + len);
    assert_int_equal(off_out, off_wr);

    validate_data(fd_out, off_wr, data + off_rd, len);

    /*
     * Try copying using an offset present in a buffer for file_in and the
     * file offset for file_out.
     */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    off_in = off_rd;

    len_copy = sftp_copy_file_range(file_in, &off_in, file_out, NULL, len);
    assert_int_equal(len_copy, len);

    /* Ensure that the offset got updated correctly in the supplied buffer */
    assert_int_equal(off_in, off_rd + len);

    /* Ensure that file_in's offsets didn't get updated but file_out's did */
    get_sftp_file_offsets(file_in, &off_in, file_out, &off_out);
    assert_int_equal(off_in, off_rd);
    assert_int_equal(off_out, off_wr + len);

    validate_data(fd_out, off_wr, data + off_rd, len);

    /*
     * Ensure that requesting to copy more bytes than the bytes which are
     * available from the read offset uptil EOF leads to only the available
     * bytes getting copied.
     */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    len_copy = sftp_copy_file_range(file_in, NULL, file_out, NULL,
                                    strlen(data) + 1);
    assert_int_equal(len_copy, strlen(data) - off_rd);

    validate_data(fd_out, off_wr, data + off_rd, len_copy);

    /*
     * Ensure that passing 0 as the number of bytes to copy leads to data
     * getting copied from file_in starting from the read offset until EOF
     * is encountered.
     */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    len_copy = sftp_copy_file_range(file_in, NULL, file_out, NULL, 0);
    assert_int_equal(len_copy, strlen(data) - off_rd);

    validate_data(fd_out, off_wr, data + off_rd, len_copy);

    /*
     * Ensure that specifying read offset > offset of last byte in file_in
     * doesn't copy anything.
     */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);
    off_in = strlen(data) + 10;
    len_copy = sftp_copy_file_range(file_in, &off_in, file_out, NULL, len);
    assert_int_equal(len_copy, 0);

    /* Negative tests start */
    set_sftp_file_offsets(file_in, off_rd, file_out, off_wr);

    len_copy = sftp_copy_file_range(NULL, NULL, file_out, NULL, len);
    assert_int_equal(len_copy, SSH_ERROR);

    len_copy = sftp_copy_file_range(file_in, NULL, NULL, NULL, len);
    assert_int_equal(len_copy, SSH_ERROR);

    rc = sftp_close(file_in);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_close(file_out);
    assert_int_equal(rc, SSH_OK);

    rc = close(fd_out);
    assert_int_equal(rc, 0);

    /*
     * Ensure that sftp_copy_file_range() fails when file_in and file_out are
     * opened using different sftp sessions.
     */
    tmp_sftp = sftp_new(s->ssh.session);
    assert_non_null(tmp_sftp);

    rc = sftp_init(tmp_sftp);
    assert_int_equal(rc, 0);

    file_in = sftp_open(t->sftp, file_in_name, O_RDONLY, 0);
    assert_non_null(file_in);

    file_out = sftp_open(tmp_sftp, file_out_name, O_WRONLY, 0);
    assert_non_null(file_out);

    len_copy = sftp_copy_file_range(file_in, NULL, file_out, NULL, 0);
    assert_int_equal(len_copy, SSH_ERROR);

    rc = sftp_close(file_in);
    assert_int_equal(rc, SSH_OK);

    rc = sftp_close(file_out);
    assert_int_equal(rc, SSH_OK);

    sftp_free(tmp_sftp);

    rc = unlink(file_in_name);
    assert_int_equal(rc, 0);

    rc = unlink(file_out_name);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_copy_file_range,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
