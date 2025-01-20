#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/callbacks.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>

static int auth_callback(const char *prompt,
                         char *buf,
                         size_t len,
                         int echo,
                         int verify,
                         void *userdata)
{
    return 0; // success for instance
}

// static int sshd_setup(void **state)
// {
//     torture_setup_sshd_server(state,false);
//     return 0;
// }

// static int sshd_teardown(void **state)
// {
//     torture_teardown_sshd_server(state);
//     return 0;
// }

static int  session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc,errno);

    s->ssh.session = torture_ssh_session(s,TORTURE_SSH_SERVER,NULL,TORTURE_SSH_USER_ALICE,NULL);
    assert_non_null(s->ssh.session);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);
    teardown(state)
    return 0;
}

static int setup(void **state)
{
    ssh_callbacks cb;

    cb = malloc(sizeof(struct ssh_callbacks_struct));
    assert_non_null(cb);
    ZERO_STRUCTP(cb);

    cb->userdata = (void *) 0x0badc0de;
    cb->auth_function = auth_callback;

    ssh_callbacks_init(cb);
    *state = cb;

    return 0;
}

static int teardown(void **state)
{
    free(*state);

    return 0;
}


static void torture_auth_callback(void **state)
{
    int rc;
    ssh_callbacks cb;
    char buf[256];
    int buf_length = sizeof(buf);
    const char *prompt = "Please Enter Password: ";
    // void **(state); //unused

    rc = setup(&cb);
    assert_int_equal(rc,0);

    rc = cb->auth_function(prompt,buf,buf_length,0,0,cb->userdata);
    assert_int_equal(rc,0);
}

int torture_run_tests(void) 
{
    int rc;
    struct CMUnitTest tests[] = 
    {
        cmocka_unit_test_setup_teardown(torture_auth_callback,
                                        session_setup,
                                        session_teardown)
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,NULL,NULL);
    ssh_finalize();
    return rc;
    
}