#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"
#include "string.h"

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

static void torture_sftp_copy_data(void **state)
{
    struct torture_state *s = *state;
    struct torture_sftp *t = s->ssh.tsftp;
    int rc;

    char read_file_handle[128] = {0};
    char write_file_handle[128] = {0};

    const char *content_1 = "This is the data from the read file.";
    char *content_2;
    size_t bytes_written;
    size_t bytes_read;

    int link1, link2;
    char fd1[128];
    char fd2[128];

    FILE *fd_read;
    FILE *fd_write;

    snprintf(read_file_handle, sizeof(read_file_handle),
             "%s/libssh_sftp_copy_data_1.txt", t->testdir);
    snprintf(write_file_handle, sizeof(write_file_handle),
             "%s/libssh_sftp_copy_data_2.txt", t->testdir);

    /* Create a file to read from. */
    fd_read = fopen(read_file_handle, "w");
    if (fd_read == NULL) {
        skip();
    }

    bytes_written = fwrite(content_1, 1, strlen(content_1), fd_read);
    if (bytes_written != strlen(content_1)){
        skip();
    }
    fclose(fd_read);

    link1 = open(read_file_handle, O_RDONLY, S_IRWXU);
    link2 = open(write_file_handle, O_CREAT | O_WRONLY, S_IRWXU);

    sprintf(fd1, "%d", link1);
    sprintf(fd2, "%d", link2);

    rc = sftp_copy_data(t->sftp, fd1, 0, 0, fd2, 0);
    printf("%i %s %s \n", rc, fd1, fd2);
    assert_int_equal(rc, 0);

    fd_write = fopen(write_file_handle, "w");
    if (fd_write == NULL){
        skip();
    }

    content_2 = (char *)malloc(bytes_written);
    bytes_read = fread(content_2, 1, bytes_written, fd_write);
    if (bytes_read != bytes_written){
        assert_int_equal(1, 0);
        skip();
    }
    assert_string_equal(content_1, content_2);

    fclose(fd_write);

    /*
     * Call the function with same read-from-handle and write-from-handle.
     * This should fail.
    */
    rc = sftp_copy_data(t->sftp, fd1, 0, strlen(content_1), fd1, 0);
    assert_int_not_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_sftp_copy_data,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
