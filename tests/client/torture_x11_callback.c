#include "config.h"

#include "torture.h"
#include "torture_key.h"
#include <libssh/libssh.h>
#include <pthread.h>

#define TEST_PORT 3333

static int setup(void **state){
    return 0;
}

static int teardown(void **state){
    return 0;
}

static void* client_thread(void* userdata){

    ssh_session session;
    int port = TEST_PORT;
    int rc;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, "foo");

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_password(session, "foo", "bar");
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    return NULL;
}

static int auth_password(ssh_session session, const char *user, const char *password, void *userdata){
    fprintf(stdout, "\n none success\n");
    return SSH_AUTH_SUCCESS;
}

static void torture_x11_callback_check(void **state){

    pthread_t client_pthread;
    ssh_bind bind;
    ssh_session session;
    int rc;
    const char *testkey;
    char testkey_path[] = "/tmp/libssh_hostkey_XXXXXX";
    int port = TEST_PORT;
    ssh_event event;

    struct ssh_server_callbacks_struct server_cb = {
        .auth_password_function = auth_password,
    };

    testkey = torture_get_testkey(SSH_KEYTYPE_RSA, 0);
    torture_write_file(testkey_path, testkey);

    bind = torture_ssh_bind("localhost", port, SSH_KEYTYPE_RSA, testkey_path);
    assert_non_null(bind);

    rc = pthread_create(&client_pthread, NULL, client_thread, NULL);
    assert_int_equal(rc, 0);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_bind_accept(bind, session);
    assert_int_equal(SSH_OK, rc);

    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    rc = ssh_handle_key_exchange(session);
    assert_int_equal(rc, SSH_OK);

    event =  ssh_event_new();
    assert_non_null(event);

    ssh_event_add_session(event, session);

    rc = SSH_OK;
    rc = ssh_event_dopoll(event, 100);

    rc = pthread_join(client_pthread, NULL);
    assert_int_equal(rc, 1);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_x11_callback_check,
                                        setup,
                                        teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);

    ssh_finalize();

    return rc;
}
