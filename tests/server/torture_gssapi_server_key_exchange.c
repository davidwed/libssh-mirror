#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libssh/libssh.h"
#include "libssh/crypto.h"
#include "torture.h"
#include "torture_key.h"

#include "test_server.h"
#include "default_cb.h"

struct test_server_st {
    struct torture_state *state;
    struct server_state_st *ss;
    char *cwd;
};

static void
free_test_server_state(void **state)
{
    struct test_server_st *tss = *state;

    torture_free_state(tss->state);
    SAFE_FREE(tss);
}

static void
setup_config(void **state)
{
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;
    struct test_server_st *tss = NULL;

    char ed25519_hostkey[1024] = {0};
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    // char trusted_ca_pubkey[1024];

    char sshd_path[1024];
    char log_file[1024];
    char kdc_env[255] = {0};
    int rc;

    assert_non_null(state);

    tss = (struct test_server_st *)calloc(1, sizeof(struct test_server_st));
    assert_non_null(tss);

    torture_setup_socket_dir((void **)&s);
    assert_non_null(s->socket_dir);
    assert_non_null(s->gss_dir);

    torture_set_kdc_env_str(s->gss_dir, kdc_env, sizeof(kdc_env));
    torture_set_env_from_str(kdc_env);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    snprintf(sshd_path, sizeof(sshd_path), "%s/sshd", s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(log_file, sizeof(log_file), "%s/sshd/log", s->socket_dir);

    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);
    torture_write_file(ed25519_hostkey,
                       torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0));

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0));

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(ecdsa_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0));

    /* Create default server state */
    ss = (struct server_state_st *)calloc(1, sizeof(struct server_state_st));
    assert_non_null(ss);

    ss->address = strdup("127.0.0.10");
    assert_non_null(ss->address);

    ss->port = 22;

    ss->ecdsa_key = strdup(ecdsa_hostkey);
    assert_non_null(ss->ecdsa_key);

    ss->ed25519_key = strdup(ed25519_hostkey);
    assert_non_null(ss->ed25519_key);

    ss->rsa_key = strdup(rsa_hostkey);
    assert_non_null(ss->rsa_key);

    ss->host_key = NULL;

    /* Use default username and password (set in default_handle_session_cb) */
    ss->expected_username = NULL;
    ss->expected_password = NULL;

    /* not to mix up the client and server messages */
    ss->verbosity = torture_libssh_verbosity();
    ss->log_file = strdup(log_file);

    ss->auth_methods = SSH_AUTH_METHOD_GSSAPI_KEYEX;

#ifdef WITH_PCAP
    ss->with_pcap = 1;
    ss->pcap_file = strdup(s->pcap_file);
    assert_non_null(ss->pcap_file);
#endif

    /* TODO make configurable */
    ss->max_tries = 3;
    ss->error = 0;

    /* Use the default session handling function */
    ss->handle_session = default_handle_session_cb;
    assert_non_null(ss->handle_session);

    /* Do not use global configuration */
    ss->parse_global_config = false;

    /* Enable GSSAPI key exchange */
    ss->gssapi_key_exchange = true;
    ss->gssapi_key_exchange_algs = "gss-group14-sha256-,gss-group16-sha512-";

    tss->state = s;
    tss->ss = ss;

    *state = tss;
}

static int
setup_default_server(void **state)
{
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;
    struct test_server_st *tss = NULL;
    char pid_str[1024] = {0};
    pid_t pid;
    int rc;

    setup_config(state);

    tss = *state;
    ss = tss->ss;
    s = tss->state;

    setenv("NSS_WRAPPER_HOSTNAME", "server.libssh.site", 1);
    /* Start the server using the default values */
    pid = fork_run_server(ss, free_test_server_state, &tss);
    if (pid < 0) {
        fail();
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    torture_write_file(s->srv_pidfile, (const char *)pid_str);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");

    /* Wait until the sshd is ready to accept connections */
    rc = torture_wait_for_daemon(5);
    assert_int_equal(rc, 0);

    *state = tss;

    return 0;
}

static int
teardown_default_server(void **state)
{
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;
    struct test_server_st *tss = NULL;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ss = tss->ss;
    assert_non_null(ss);

    /* This function can be reused */
    torture_teardown_sshd_server((void **)&s);

    free_server_state(tss->ss);
    SAFE_FREE(tss->ss);
    SAFE_FREE(tss);

    return 0;
}

static int
session_setup(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    int verbosity = torture_libssh_verbosity();
    char *cwd = NULL;
    bool b = false;
    int rc;

    assert_non_null(tss);

    /* Make sure we do not test the agent */
    unsetenv("SSH_AUTH_SOCK");

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tss->cwd = cwd;

    s = tss->state;
    assert_non_null(s);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);
    rc = ssh_options_set(s->ssh.session,
                         SSH_OPTIONS_USER,
                         TORTURE_SSH_USER_ALICE);
    assert_int_equal(rc, SSH_OK);
    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int
session_teardown(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    int rc = 0;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    rc = torture_change_dir(tss->cwd);
    assert_int_equal(rc, 0);

    SAFE_FREE(tss->cwd);

    return 0;
}


static void
torture_gssapi_server_key_exchange(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Valid */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site\n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site\n"
        "kadmin.local addprinc -pw bar alice\n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    torture_teardown_kdc_server((void **)&s);
}

static void
torture_gssapi_server_key_exchange_no_tgt(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Don't run kinit */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site \n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site \n"
        "kadmin.local addprinc -pw bar alice \n"
        "kadmin.local list_principals",

        /* No TGT */
        "");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, 0);

    assert_int_not_equal(session->current_crypto->kex_type, SSH_GSS_KEX_DH_GROUP14_SHA256);
    assert_int_not_equal(session->current_crypto->kex_type, SSH_GSS_KEX_DH_GROUP16_SHA512);

    torture_teardown_kdc_server((void **)&s);
}

static void
torture_gssapi_server_key_exchange_gss_group14_sha256(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Valid */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site \n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site \n"
        "kadmin.local addprinc -pw bar alice \n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS, "gss-group14-sha256-");
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, 0);

    assert_int_equal(session->current_crypto->kex_type, SSH_GSS_KEX_DH_GROUP14_SHA256);

    torture_teardown_kdc_server((void **)&s);
}

static void
torture_gssapi_server_key_exchange_gss_group16_sha512(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Valid */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site \n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site \n"
        "kadmin.local addprinc -pw bar alice \n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE_ALGS, "gss-group16-sha512-");
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, 0);

    assert_int_equal(session->current_crypto->kex_type, SSH_GSS_KEX_DH_GROUP16_SHA512);

    torture_teardown_kdc_server((void **)&s);
}

static void
torture_gssapi_server_key_exchange_auth(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session;
    int rc;
    bool t = true;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Valid */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site\n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site\n"
        "kadmin.local addprinc -pw bar alice\n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &t);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_gssapi_keyex(session);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    torture_teardown_kdc_server((void **)&s);
}

static void
torture_gssapi_server_key_exchange_no_auth(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    ssh_session session = NULL;
    int rc;
    bool f = false;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    /* Valid */
    torture_setup_kdc_server(
        (void **)&s,
        "kadmin.local addprinc -randkey host/server.libssh.site\n"
        "kadmin.local ktadd -k $(dirname $0)/d/ssh.keytab host/server.libssh.site\n"
        "kadmin.local addprinc -pw bar alice\n"
        "kadmin.local list_principals",

        "echo bar | kinit alice");

    /* Don't do GSSAPI Key Exchange */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_GSSAPI_KEY_EXCHANGE, &f);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    /* Still try to do "gssapi-keyex" auth */
    rc = ssh_userauth_gssapi_keyex(session);
    assert_int_equal(rc, SSH_AUTH_ERROR);

    torture_teardown_kdc_server((void **)&s);
}

int
torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange_no_tgt,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange_gss_group14_sha256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange_gss_group16_sha512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange_auth,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_gssapi_server_key_exchange_no_auth,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
                                setup_default_server,
                                teardown_default_server);
    ssh_finalize();

    /* pthread_exit() won't return anything so error should be returned prior */
    if (rc != 0) {
        return rc;
    }

    /* Required for freeing memory allocated by GSSAPI */
    pthread_exit(NULL);
}
