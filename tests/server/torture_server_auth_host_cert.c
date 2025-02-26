#include "config.h"

#include "torture.h"
#include "torture_key.h"
#include "libssh/pki.h"
#include <libssh/libssh.h>
#include <errno.h>
#include <pwd.h>

#define TMP_FILE_TEMPLATE "known_hosts_XXXXXX"
#define NUM_SERVER_KEYS 3
enum ssh_keytypes_e server_cert_keytypes[] = {SSH_KEYTYPE_RSA_CERT01,
                                              SSH_KEYTYPE_ECDSA_P521_CERT01,
                                              SSH_KEYTYPE_ED25519_CERT01};

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

static int libssh_server_setup(void **state)
{
    struct torture_state *s = NULL;
    char log_file[1024];

    setenv("TORTURE_SKIP_CLEANUP", "1", 1);

    torture_setup_socket_dir((void **)&s);
    torture_setup_create_libssh_config((void **)&s);

    snprintf(log_file,
             sizeof(log_file),
             "%s/sshd/log",
             s->socket_dir);

    s->log_file = strdup(log_file);
    assert_non_null(s->log_file);

    torture_setup_libssh_server((void **)&s, "./test_server/test_server");

    *state = s;
    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static int
update_server_config_host_cert(void **state,
                             enum ssh_keytypes_e cert_type,
                             bool libssh_server,
                             bool want_expired)
{
    struct torture_state *s = NULL;
    char host_certificate[1024];
    char additional_config[4096];
    const char *cert = NULL;
    int rc;

    s = *state;

    snprintf(host_certificate,
             sizeof(host_certificate),
             "%s/sshd/ssh_host_key-cert.pub",
             s->socket_dir);

    if (want_expired) {
        cert = torture_get_testkey_expired_server_host_cert(cert_type);
    } else {
        cert = torture_get_testkey_host_cert(cert_type);
    }

    if (cert == NULL) {
        return SSH_ERROR;
    }

    torture_write_file(host_certificate, cert);

    snprintf(additional_config,
             sizeof(additional_config),
             "HostCertificate %s",
             host_certificate);

    if (libssh_server) {
        /* Store the configuration in internal structure */
        SAFE_FREE(s->srv_additional_config);
        s->srv_additional_config = strdup(additional_config);
        assert_non_null(s->srv_additional_config);

        /* Rewrite the configuration file */
        torture_setup_create_libssh_config(state);
        SAFE_FREE(s->srv_additional_config);

        /* Reload the server */
        rc = torture_terminate_process(s->srv_pidfile);
        assert_return_code(rc, errno);

        torture_setup_libssh_server(state, "./test_server/test_server");
    } else {
        rc = torture_update_sshd_config(state, additional_config);
    }

    return rc;
}

static char *
setup_known_hosts_file(void **state, bool want_revoked)
{
    struct torture_state *s = *state;
    char tmp_file[1024] = {0};
    char *known_hosts_file = NULL;
    const char *marker_s = NULL;
    FILE *file = NULL;
    int rc;

    snprintf(tmp_file,
             sizeof(tmp_file),
             "%s/%s",
             s->socket_dir,
             TMP_FILE_TEMPLATE);

    known_hosts_file = torture_create_temp_file(tmp_file);
    if (known_hosts_file == NULL) {
        return NULL;
    }

    file = fopen(known_hosts_file, "w");
    if (file == NULL) {
        goto fail;
    }

    if (want_revoked) {
        marker_s = "@revoked";
    } else {
        marker_s = "@cert-authority";
    }

    rc = fprintf(file,
                 "%s 127.0.0.10 %s\n",
                 marker_s,
                 torture_get_testkey_host_ca_public());
    fclose(file);
    if (rc < 0) {
        goto fail;
    }

    return known_hosts_file;

fail:
    SAFE_FREE(known_hosts_file);
    return NULL;
}

static void
torture_server_host_cert_auth(void **state, bool libssh_server)
{
    struct torture_state *s = *state;
    int rc, found, i;
    ssh_session session = s->ssh.session;
    char *known_hosts_file = NULL;
    enum ssh_keytypes_e cert_type;

    known_hosts_file = setup_known_hosts_file(state, false);
    assert_non_null(known_hosts_file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    for (i = 0; i < NUM_SERVER_KEYS; i++) {
        cert_type = server_cert_keytypes[i];

        if (ssh_fips_mode() && cert_type == SSH_KEYTYPE_ED25519_CERT01) {
            continue;
        }

        rc = update_server_config_host_cert(state,
                                            cert_type,
                                            libssh_server,
                                            false);
        assert_int_equal(rc, SSH_OK);

        rc = ssh_connect(session);
        assert_ssh_return_code(session, rc);

        found = ssh_session_is_known_server(session);
        assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

        ssh_disconnect(session);
        SAFE_FREE(known_hosts_file);
    }
    SAFE_FREE(known_hosts_file);
}

static void
torture_server_host_cert_auth_revoked(void **state, bool libssh_server)
{
    struct torture_state *s = *state;
    int rc, found, i;
    ssh_session session = s->ssh.session;
    char *known_hosts_file = NULL;
    enum ssh_keytypes_e cert_type;

    known_hosts_file = setup_known_hosts_file(state, true);
    assert_non_null(known_hosts_file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    for (i = 0; i < NUM_SERVER_KEYS; i++) {
        cert_type = server_cert_keytypes[i];

        if (ssh_fips_mode() && cert_type == SSH_KEYTYPE_ED25519_CERT01) {
            continue;
        }

        rc = update_server_config_host_cert(state,
                                            cert_type,
                                            libssh_server,
                                            false);
        assert_int_equal(rc, SSH_OK);

        rc = ssh_connect(session);
        assert_ssh_return_code(session, rc);

        found = ssh_session_is_known_server(session);
        assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

        ssh_disconnect(session);
        SAFE_FREE(known_hosts_file);
    }
    SAFE_FREE(known_hosts_file);
}

static void
torture_server_host_cert_auth_expired(void **state, bool libssh_server)
{
    struct torture_state *s = *state;
    int rc, found, i;
    ssh_session session = s->ssh.session;
    char *known_hosts_file = NULL;
    enum ssh_keytypes_e cert_type;

    known_hosts_file = setup_known_hosts_file(state, false);
    assert_non_null(known_hosts_file);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, known_hosts_file);
    assert_ssh_return_code(session, rc);

    for (i = 0; i < NUM_SERVER_KEYS; i++) {
        cert_type = server_cert_keytypes[i];

        if (ssh_fips_mode() && cert_type == SSH_KEYTYPE_ED25519_CERT01) {
            continue;
        }

        rc = update_server_config_host_cert(state,
                                            cert_type,
                                            libssh_server,
                                            true);
        assert_int_equal(rc, SSH_OK);

        rc = ssh_connect(session);
        assert_ssh_return_code(session, rc);

        found = ssh_session_is_known_server(session);
        assert_int_equal(found, SSH_KNOWN_HOSTS_ERROR);

        ssh_disconnect(session);
        SAFE_FREE(known_hosts_file);
    }
    SAFE_FREE(known_hosts_file);
}

/************* SSHD_SERVER *************/

static void
torture_sshd_server_host_cert_auth(void **state)
{
    torture_server_host_cert_auth(state, false);
}

static void
torture_sshd_server_host_cert_auth_revoked(void **state)
{
    torture_server_host_cert_auth_revoked(state, false);
}

static void
torture_sshd_server_host_cert_auth_expired(void **state)
{
    torture_server_host_cert_auth_expired(state, false);
}

/************* LIBSSH_SERVER *************/

static void
torture_libssh_server_host_cert_auth(void **state)
{
    torture_server_host_cert_auth(state, true);
}

static void
torture_libssh_server_host_cert_auth_revoked(void **state)
{
    torture_server_host_cert_auth_revoked(state, true);
}

static void
torture_libssh_server_host_cert_auth_expired(void **state)
{
    torture_server_host_cert_auth_expired(state, true);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest sshd_tests[] = {
        cmocka_unit_test_setup_teardown(torture_sshd_server_host_cert_auth,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_sshd_server_host_cert_auth_revoked,
            session_setup,
            session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_sshd_server_host_cert_auth_expired,
            session_setup,
            session_teardown),
    };

    struct CMUnitTest libssh_tests[] = {
        cmocka_unit_test_setup_teardown(torture_libssh_server_host_cert_auth,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_libssh_server_host_cert_auth_revoked,
            session_setup,
            session_teardown),
        cmocka_unit_test_setup_teardown(
            torture_libssh_server_host_cert_auth_expired,
            session_setup,
            session_teardown),
    };

    ssh_init();

    torture_filter_tests(sshd_tests);
    cmocka_run_group_tests(sshd_tests, sshd_setup, sshd_teardown);

    torture_filter_tests(libssh_tests);
    rc = cmocka_run_group_tests(libssh_tests,
                                libssh_server_setup,
                                sshd_teardown);

    ssh_finalize();
    return rc;
}
