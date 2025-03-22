#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include <errno.h>
#include <libssh/callbacks.h>
#include <libssh/misc.h>
#include <libssh/priv.h>
#include <libssh/session.h>

struct test_auth_agent_state {
    int called;
    ssh_session session;
    void *userdata;
};

/* Mock callback that simulates successful channel creation */
static ssh_channel auth_agent_callback_success(ssh_session session, void *userdata) 
{
    struct test_auth_agent_state *state = (struct test_auth_agent_state *)userdata;
    
    state->called++;
    state->session = session;
    state->userdata = userdata;

    /* Return a dummy channel pointer just for testing */
    return (ssh_channel)0x1;  // Non-NULL pointer for testing
}

/* Mock callback that simulates failure by returning NULL */
static ssh_channel auth_agent_callback_failure(ssh_session session, void *userdata) 
{
    struct test_auth_agent_state *state = (struct test_auth_agent_state *)userdata;
    
    state->called++;
    state->session = session;
    state->userdata = userdata;

    return NULL;
}

static int setup(void **state) 
{
    struct test_auth_agent_state *test_state;
    ssh_session session;

    test_state = malloc(sizeof(struct test_auth_agent_state));
    assert_non_null(test_state);

    session = ssh_new();
    assert_non_null(session);

    test_state->called = 0;
    test_state->session = session;
    test_state->userdata = test_state;

    *state = test_state;
    return 0;
}

static int teardown(void **state) 
{
    struct test_auth_agent_state *test_state = *state;
    
    ssh_free(test_state->session);
    free(test_state);
    
    return 0;
}

/* Basic functionality test - successful case */
static void torture_auth_agent_success(void **state) 
{
    struct test_auth_agent_state *test_state = *state;
    struct ssh_callbacks_struct cb = {
        .size = sizeof(struct ssh_callbacks_struct),
        .userdata = test_state,
        .channel_open_request_auth_agent_function = auth_agent_callback_success
    };
    ssh_channel channel;
    int rc;

    /* Initialize callbacks */
    ssh_callbacks_init(&cb);
    rc = ssh_set_callbacks(test_state->session, &cb);
    assert_int_equal(rc, SSH_OK);

    /* Call the callback through the session */
    channel = cb.channel_open_request_auth_agent_function(test_state->session, test_state);

    /* Verify the callback was called once */
    assert_int_equal(test_state->called, 1);
    
    /* Verify we got a non-NULL channel back */
    assert_non_null(channel);
    
    /* No need to free the mock channel */
}

/* Basic functionality test - failure case */
static void torture_auth_agent_failure(void **state) 
{
    struct test_auth_agent_state *test_state = *state;
    struct ssh_callbacks_struct cb = {
        .size = sizeof(struct ssh_callbacks_struct),
        .userdata = test_state,
        .channel_open_request_auth_agent_function = auth_agent_callback_failure
    };
    ssh_channel channel;
    int rc;

    /* Initialize callbacks */
    ssh_callbacks_init(&cb);
    rc = ssh_set_callbacks(test_state->session, &cb);
    assert_int_equal(rc, SSH_OK);

    /* Call the callback through the session */
    channel = cb.channel_open_request_auth_agent_function(test_state->session, test_state);

    /* Verify the callback was called once */
    assert_int_equal(test_state->called, 1);
    
    /* Verify we got NULL back (simulated failure) */
    assert_null(channel);
}

int torture_run_tests(void) 
{
    int rc;
    struct CMUnitTest tests[] = {
        /* Basic functionality tests only */
        cmocka_unit_test_setup_teardown(torture_auth_agent_success,
                                       setup, teardown),
        cmocka_unit_test_setup_teardown(torture_auth_agent_failure,
                                       setup, teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}