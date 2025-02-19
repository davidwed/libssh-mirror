#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>

#include <errno.h>
#include <fcntl.h>
#include <gssapi.h>
#include <pwd.h>

static int
sshd_setup(void **state)
{
    struct torture_state *s = NULL;
    torture_setup_sshd_server(state, false);

    s = *state;
    s->disable_hostkeys = true;

    if (!ssh_fips_mode()) {
        /* Temporary kerberos server */
        torture_setup_kdc_server(
            state,
            "kadmin.local addprinc -randkey host/server.libssh.site \n"
            "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site \n"
            "kadmin.local addprinc -pw bar alice \n"
            "kadmin.local list_principals",

            "echo bar | kinit alice");

        torture_update_sshd_config(state,
                                "GSSAPIAuthentication yes\n"
                                "GSSAPIKeyExchange yes\n");

        torture_teardown_kdc_server(state);
    }
    return 0;
}

static int
sshd_teardown(void **state)
{
    assert_non_null(state);

    torture_teardown_sshd_server(state);

    return 0;
}

static int
session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd = NULL;
    int rc;
    bool b = false;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);

    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int
session_teardown(void **state)
{
    struct torture_state *s = *state;

    assert_non_null(s);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void
torture_gssapi_key_exchange_null(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    /* Valid */
    torture_setup_kdc_server(
        state,
        "kadmin.local addprinc -randkey host/server.libssh.site \n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site \n"
        "kadmin.local addprinc -pw bar alice \n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(s->ssh.session, rc);
    torture_teardown_kdc_server(state);
}

int
torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_gssapi_key_exchange_null,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    /* pthread_exit() won't return anything so error should be returned prior */
    if (rc != 0) {
        return rc;
    }

    /* Required for freeing memory allocated by GSSAPI */
    pthread_exit(NULL);
}
