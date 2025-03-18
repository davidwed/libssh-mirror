#include "config.h"

#include "torture.h"
#include "torture_key.h"
#include <libssh/libssh.h>
#include <pthread.h>

#define TEST_PORT 3333
#define SUCCESS (1)
#define FAILURE (2)

int x11_status = FAILURE;

static int setup(void **state){
    return 0;
}

static int teardown(void **state){
    return 0;
}

static ssh_channel x11_client_callback(
        ssh_session session,
        const char* originator_address,
        int originator_port,
        void *userdata
        ){
    ssh_channel x11_channel = ssh_channel_new(session);
    x11_status = SUCCESS;
    return x11_channel;
}

static void* client_thread(void* userdata){

    int rc;
    int port = TEST_PORT;
    int verb = 4;
    ssh_session session;
    ssh_channel channel;

    struct ssh_callbacks_struct cb = {
        .channel_open_request_x11_function = x11_client_callback,
        .userdata = NULL
    };

    ssh_callbacks_init(&cb);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_set_callbacks(session, &cb);
    assert_int_equal(rc, SSH_OK);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, "foo");
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verb);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_password(session, "foo", "bar");
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_channel_request_x11(channel, 0, NULL, NULL, 0);
    assert_int_equal(rc, SSH_OK);

    ssh_free(session);
    return NULL;
}

static int auth_password(ssh_session session, const char *user, const char *password, void *userdata){
    return SSH_AUTH_SUCCESS;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {

    ssh_channel *channel = (ssh_channel*)userdata;
    *channel = ssh_channel_new(session);
    return *channel;
}

static void x11_req_server_callback(
        ssh_session session,
        ssh_channel channel,
        int single_connection,
        const char *auth_protocol,
        const char *auth_cookie,
        uint32_t screen_number,
        void *userdata
        ){
    /* empty */
}

static void torture_x11_callback_check(void **state){

    int rc;
    int port = TEST_PORT;
    ssh_bind bind;
    ssh_session session;
    ssh_channel channel = NULL;
    ssh_event event;
    pthread_t client_pthread;
    char testkey_path[] = "/tmp/libssh_hostkey_XXXXXX";
    const char *testkey;

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &channel,
        .auth_password_function = auth_password,
        .channel_open_request_session_function = channel_open
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .channel_x11_req_function = x11_req_server_callback,
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

    ssh_callbacks_init(&channel_cb);
    ssh_callbacks_init(&server_cb);
    ssh_set_server_callbacks(session, &server_cb);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    rc = ssh_handle_key_exchange(session);
    assert_int_equal(rc, SSH_OK);

    event =  ssh_event_new();
    assert_non_null(event);

    ssh_event_add_session(event, session);

    while(channel == NULL){
        ssh_event_dopoll(event, -1);
    }

    rc = ssh_set_channel_callbacks(channel, &channel_cb);
    assert_int_equal(rc, SSH_OK);

    rc = SSH_OK;
    while(rc == SSH_OK){
        rc = ssh_event_dopoll(event, -1);
    }

    rc = pthread_join(client_pthread, NULL);
    assert_int_equal(rc, 0);

    assert_int_equal(x11_status, SUCCESS);
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
