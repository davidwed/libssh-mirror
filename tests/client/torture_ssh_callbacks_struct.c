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

struct callback_state {
    ssh_callbacks cb;
    struct torture_state *ts;
};

static int auth_callback(const char *prompt,
                         char *buf,
                         size_t len,
                         int echo,
                         int verify,
                         void *userdata)
{
    (void) prompt;
    (void) buf;
    (void) len;
    (void) echo;
    (void) verify;
    (void) userdata;
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
    struct callback_state *s;

    s = malloc(sizeof(struct callback_state));
    assert_non_null(s);

    s->ts = malloc(sizeof(struct torture_state));
    assert_non_null(s->ts);

    s->ts->ssh.session = torture_ssh_session(s->ts,
                                             TORTURE_SSH_SERVER,
                                             NULL,
                                             TORTURE_SSH_USER_ALICE,
                                             NULL);
    assert_non_null(s->ts);

    s->cb = malloc(sizeof(struct ssh_callbacks_struct));
    assert_non_null(s->cb);
    ZERO_STRUCTP(s->cb);

    s->cb->userdata = (void *) 0x0badc0de;
    s->cb->auth_function = auth_callback;

    ssh_callbacks_init(s->cb);

    *state = s;
    
    return 0;
}

static int session_teardown(void **state)
{
    struct callback_state *s = *state;
    ssh_disconnect(s->ts->ssh.session);
    ssh_free(s->ts->ssh.session);
    return 0;
}

static void torture_auth_callback(void **state)
{
    struct callback_state *s = *state;
    int rc;
    char buf[256];
    int buf_length = sizeof(buf);
    const char *prompt = "Please Enter Password: ";

    rc = s->cb->auth_function(prompt,buf,buf_length,0,0,s->cb->userdata);
    assert_int_equal(rc,0);
    // printf("Great");
    return;
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